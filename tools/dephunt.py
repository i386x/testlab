#!/usr/bin/python3
#                                                         -*- coding: utf-8 -*-
# File:    ./tools/dephunt.py
# Author:  Jiří Kučera <sanczes AT gmail.com>
# Date:    2021-03-06 15:37:15 +0100
# Project: testlab: Testing laboratory
#
# SPDX-License-Identifier: GPL-2.0-only
#
"""Hunt down RPM package dependencies."""

import argparse
import subprocess
import sys

import dnf
import dnf.util

SKIPPED_ARCHES = ("i686", "s390")


def unique(items):
    """Remove duplicates from `items`."""
    return list(set(items))


def flatten(lst):
    """Flatten a list."""
    result = []
    for item in lst:
        if isinstance(item, (list, tuple)):
            result.extend(flatten(item))
        else:
            result.append(item)
    return result


def csv2list(csv, groupdefs=None):
    """Convert comma-separated list to list."""
    items = [x.strip() for x in csv.split(",")]
    items = [x for x in items if len(x) > 0]
    if groupdefs:
        items = [
            (groupdefs.get(x[1:], x) if x.startswith("@") else x)
            for x in items
        ]
        items = flatten(items)
    return items


def xspec2list(xspec, srcname="<str>"):
    """Convert exclude specification to list."""
    groupdefs = {}
    active_group = None
    items = []

    for i, line in enumerate(xspec.split("\n"), 1):
        # Strip comment:
        pos = line.find("#")
        if pos >= 0:
            line = line[pos:]
        line = line.strip()
        if len(line) == 0:
            continue
        # Are we inside group definition?
        if active_group:
            groupdefs[active_group].extend(csv2list(line, groupdefs))
            if not line.endswith(","):
                active_group = None
            continue
        pos = line.find("=")
        # Ordinary csv
        if pos < 0:
            items.extend(csv2list(line, groupdefs))
            continue
        # Group definition
        gname, gbody = [x.strip() for x in line.split("=", 1)]
        if len(gname) == 0:
            print(f"{srcname}:{i}: Group name expected.", file=sys.stderr)
            sys.exit(1)
        groupdefs[gname] = []
        if len(gbody) == 0:
            active_group = gname
            continue
        groupdefs[gname].extend(csv2list(gbody, groupdefs))
        if gbody.endswith(","):
            active_group = gname
    return items


def dict2opts(opts):
    """Convert `opts` to list of options."""
    result = []
    for opt in opts:
        if isinstance(opts[opt], bool):
            result.append(f"--{opt}")
        else:
            result.append(f"--{opt}={opts[opt]}")
    return result


def opts2dict(opts):
    """Convert `opts` to dict."""
    result = {}
    for opt in flatten(opts):
        opt = opt.split("=", 1)
        if len(opt) > 1:
            result[opt[0]] = opt[1]
        else:
            result[opt[0]] = True
    return result


def runcmd(cmd):
    """Run `cmd`."""
    try:
        return subprocess.run(
            cmd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            encoding="utf-8",
        ).stdout
    except subprocess.CalledProcessError as exc:
        print(
            f"Command {exc.cmd} has exited with {exc.returncode} and a message"
            f":\n\n  {exc.output}\n",
            file=sys.stderr,
        )
    return None


class PackageFlags:
    """Package flags."""

    WEAK = 1
    BUILD_REQUIRE = 2
    REQUIRE = 4
    INSTALLED = 8
    UNAVAILABLE = 16
    __slots__ = ("__flags",)

    def __init__(self, flags=0):
        """Initialize flags."""
        self.__flags = flags

    def set(self, flags):
        """Set the `flags`."""
        self.__flags |= flags

    def reset(self, flags):
        """Reset the `flags`."""
        self.__flags &= ~flags

    def test(self, flags):
        """Test whether `flags` are set."""
        return self.__flags & flags == flags

    def __str__(self):
        """Return string representation."""
        flags = self.__flags
        lflags = []
        for spec in ("_W", "_B", "_R", "_IU?"):
            bshift = {2: 1, 4: 2}[len(spec)]
            bmask = (1 << bshift) - 1
            lflags.append(spec[flags & bmask])
            flags >>= bshift
        lflags.reverse()
        return "".join(lflags)

    def __repr__(self):
        """Return string representation."""
        return str(self)

    @staticmethod
    def is_weak(pkg):
        """Test whether `pkg` is a weak dependency."""
        return pkg.flags.test(PackageFlags.WEAK)

    @staticmethod
    def is_not_weak(pkg):
        """Test whether `pkg` is not a weak dependency."""
        return not PackageFlags.is_weak(pkg)


class PackageInfo:
    """Information about a package."""

    __slots__ = ("name", "evr", "arch", "source_name", "reponame")

    def __init__(self, *args):
        """Initialize the info structure."""
        self.name = args[0]
        self.evr = args[1]
        self.arch = args[2]
        self.source_name = args[3] if args[3] != "(none)" else None
        self.reponame = args[4]


class Package:
    """A wrapper around `dnf.package.Package`."""

    __slots__ = ("pkg", "flags", "dependency_of", "build_dependency_of")

    def __init__(self, pkg):
        """Initialize wrapper."""
        self.pkg = pkg
        self.flags = PackageFlags()
        self.dependency_of = []
        self.build_dependency_of = []

    def add_dependant(self, pkg):
        """Add `pkg` to the what requires list."""
        obj = self.__class__(pkg)
        if pkg.arch == "src":
            self.build_dependency_of.append(obj)
        else:
            self.dependency_of.append(obj)

    def __eq__(self, other):
        """Test the equality with `other`."""
        return (
            self.pkg.name == other.pkg.name
            and self.pkg.evr == other.pkg.evr
            and self.pkg.arch == other.pkg.arch
            and self.pkg.source_name == other.pkg.source_name
            and (
                self.pkg.reponame == other.pkg.reponame
                or "@System" in (self.pkg.reponame, other.pkg.reponame)
            )
        )

    def __str__(self):
        """Return string representation."""
        return (
            f"{self.pkg.name}-{self.pkg.evr}.{self.pkg.arch}"
            f" ({self.pkg.source_name}, {self.pkg.reponame})"
        )

    def __repr__(self):
        """Return string representation."""
        return str(self)

    def printme(self, **kwargs):
        """Print information about the package."""
        indent = kwargs.get("indent", "")
        showlists = kwargs.get("showlists", False)
        stream = kwargs.get("stream", sys.stdout)

        if showlists:
            stream.write(f"{indent}{self}\n")
        else:
            stream.write(f"{indent}{self.pkg.name:<40}{self.pkg.evr:<40}")
            stream.write(f"{self.pkg.arch:<10}{self.pkg.source_name:<40}")
            stream.write(f"{self.pkg.reponame:<15}{self.flags}\n")
            return
        if len(self.dependency_of) > 0:
            stream.write(f"{indent * 2}dependency of:\n")
        for pkg in self.dependency_of:
            stream.write(f"{indent * 3}{pkg}\n")
        if len(self.build_dependency_of) > 0:
            stream.write(f"{indent * 2}build dependency of:\n")
        for pkg in self.build_dependency_of:
            stream.write(f"{indent * 3}{pkg}\n")


class PackageSet(dict):
    """Set of packages."""

    __slots__ = ()

    def add(self, pkg, flags=0):
        """Add `pkg` to the set. Set `flags` if there are some."""
        if hasattr(pkg, "is_package"):
            if not pkg.is_package():
                print(f"{str(pkg)} is not a package", file=sys.stderr)
                sys.exit(1)
            pkg = pkg.pkg
        if not isinstance(pkg, dnf.package.Package):
            print(
                f"{str(pkg)} is not a package (it is {type(pkg).__name__})",
                file=sys.stderr,
            )
            sys.exit(1)
        if pkg.arch in SKIPPED_ARCHES:
            return
        if pkg.name not in self:
            self[pkg.name] = Package(pkg)
        else:
            pkg1, pkg2 = self[pkg.name], Package(pkg)
            if pkg1 != pkg2:
                print(f"{pkg.name}: {pkg1} != {pkg2}", file=sys.stderr)
                sys.exit(1)
        self[pkg.name].flags.set(flags)

    def printme(self, **kwargs):
        """Print the content of the package set."""
        banner = kwargs.get("banner")
        stream = kwargs.get("stream", sys.stdout)
        fltr = kwargs.get("fltr")

        skeys = sorted(list(self.keys()))
        if fltr:
            skeys = [x for x in skeys if fltr(self[x])]
        if len(skeys) == 0:
            return
        if banner:
            stream.write(f"{banner}\n")
        for key in skeys:
            self[key].printme(**kwargs)


class Bag:
    """Bag of packages to be installed and its dependencies."""

    __slots__ = (
        "opts",
        "base",
        "to_be_installed",
        "already_installed",
        "dependencies",
        "unavailable",
    )

    def __init__(self, opts=None):
        """Initialize bag."""
        self.opts = opts or {}
        self.base = self.make_base(self.opts)
        self.to_be_installed = PackageSet()
        self.already_installed = PackageSet()
        self.dependencies = PackageSet()
        self.unavailable = []

    @staticmethod
    def matches(sack, **query):
        """
        Test whether `sack` matches `query`.

        Return a pair where the first value is `True` if `sack` matches `query`
        and the second value is the selector that was used for the test.
        """
        selector = dnf.selector.Selector(sack)
        selector.set(**query)
        return selector.matches(), selector

    @staticmethod
    def make_base(opts=None):
        """Return initialized dnf base."""
        base = dnf.Base()
        if opts:
            base.conf._configure_from_options(opts)
        base.read_all_repos()
        base.fill_sack()
        base.repos.enable_source_repos()
        return base

    def _find_rpms(self, names):
        """Look for binary rpms."""
        packages = []
        for name in names:
            # Taken from builddep dnf core plugin
            query = dnf.subject.Subject(name).get_best_query(self.base.sack)
            packages.extend(query.filter(arch__neq="src").run())
        return packages

    def _find_srpms(self, names):
        """Look for source rpms."""
        return (
            # Taken from builddep dnf core plugin
            self.base.sack.query()  # Get the query
            .available()  # Limit to packages available from repositories
            .filter(name=names, arch="src")  # Select only source packages
            .latest()  # Limit selected packages to latest ones
            .run()  # Evaluate the query
        )

    def _get_provides(self, pkg_spec):
        """Get provides from `pkg_spec`."""
        provides = []
        for name in pkg_spec:
            for pkg in self._find_srpms([name]):
                provides.extend(
                    [str(x).split(" = ")[0].strip() for x in pkg.provides]
                )
        provides = [
            x
            for x in provides
            if not x.endswith("-debuginfo") and not x.endswith("-debugsource")
        ]
        return sorted(unique(provides))

    def _install_requires(self, req):
        """
        Add `req` to the transaction.

        If `req` is not available, add it to the list of unavailable packages.
        If `req` is already installed, add it to the list of already installed
        packages. If `req` is available, add it to the transaction.

        The code of this method is taken from the `builddep` dnf core plugin.
        """
        # Try find something by provides
        found, selector = self.matches(self.base.sack, provides=req)
        if not found and req.startswith("/"):
            # Try find something by file
            found, selector = self.matches(self.base.sack, file=req)
        if not found and not req.startswith("("):
            if req not in self.unavailable:
                self.unavailable.append(req)
            return
        # Found or `req` starts with "("
        if found:
            for pkg in self.base._sltr_matches_installed(selector):
                self.already_installed.add(pkg, flags=PackageFlags.INSTALLED)
        self.base._goal.install(select=selector, optional=False)

    def _install(self, packages):
        """Add `packages` to the bag."""
        for pkg in packages:
            for req in pkg.requires:
                self._install_requires(str(req))

    def install(self, pkg_spec, srpm=False, source=False):
        """
        Add packages matching `pkg_spec` to the bag.

        `pkg_spec` can be the name or the list of names of packages to be
        installed. If `srpm` is `True`, `pkg_spec` is treated as a source
        packages and they are expanded to their provides. If `source` is
        `True`, then the build dependencies are also installed.
        """
        if not isinstance(pkg_spec, list):
            pkg_spec = [pkg_spec]
        if srpm:
            pkg_spec = self._get_provides(pkg_spec)
        packages = self._find_rpms(pkg_spec)
        self._install(packages)
        for pkg in packages:
            self.to_be_installed.add(pkg)
        if source:
            packages = unique([x.source_name for x in packages] + pkg_spec)
            packages = self._find_srpms(packages)
            self._install(packages)

    @staticmethod
    def what_requires(pkg_name, dnf_opts):
        """Gather what requires `pkg_name`."""
        wrqs = []
        command = ["dnf", "-q"]
        command.extend(dict2opts(dnf_opts))
        qfmt = "%{name}/%{evr}/%{arch}/%{source_name}/%{reponame}"
        command.extend(["repoquery", "--whatrequires", pkg_name, "--qf", qfmt])
        for line in (runcmd(command) or "").split("\n"):
            line = line.strip()
            if len(line) == 0:
                continue
            parts = line.split("/")
            if len(parts) != 5:
                print(f"Invalid output:\n\n  {line}\n", file=sys.stderr)
                continue
            wrqs.append(PackageInfo(*parts))
        return wrqs

    def _fill_dependencies(self):
        """Fill dependencies."""
        bunch = dnf.util._make_lists(self.base.transaction)
        for pkg in bunch.installed:
            self.dependencies.add(pkg)
        for pkg in bunch.installed_dep:
            self.dependencies.add(pkg)
        for pkg in bunch.installed_weak:
            self.dependencies.add(pkg, flags=PackageFlags.WEAK)

    def _fill_what_requires(self, pkgset):
        """Fill what requires for every dependency in `pkgset`."""
        for dep in sorted(list(pkgset.keys())):
            pkg = pkgset[dep]
            for wrq in self.what_requires(pkg.pkg.name, self.opts):
                pkg.add_dependant(wrq)
                flag = (
                    PackageFlags.BUILD_REQUIRE
                    if wrq.arch == "src"
                    else PackageFlags.REQUIRE
                )
                if wrq.name in self.dependencies:
                    self.dependencies[wrq.name].flags.set(flag)
                if wrq.name in self.to_be_installed:
                    self.to_be_installed[wrq.name].flags.set(flag)

    def track_what_requires(self):
        """Build what requires lists."""
        self._fill_what_requires(self.to_be_installed)
        self._fill_what_requires(self.already_installed)
        self._fill_what_requires(self.dependencies)

    def resolve(self, track_wr=True):
        """Resolve the content inside the bag."""
        self.base.resolve()
        # Now we have the transaction ready
        self._fill_dependencies()
        if track_wr:
            self.track_what_requires()
        self.unavailable = sorted(self.unavailable)

    def remove_from_all(self, item):
        """Remove `item` from all package sets."""
        if item in self.to_be_installed:
            del self.to_be_installed[item]
        if item in self.already_installed:
            del self.already_installed[item]
        if item in self.dependencies:
            del self.dependencies[item]

    def exclude(self, other):
        """Exclude dependencies listed in `other` from the bag."""
        for key in other.to_be_installed:
            self.remove_from_all(key)
        for key in other.already_installed:
            self.remove_from_all(key)
        for key in other.dependencies:
            self.remove_from_all(key)
        self.unavailable = [
            x for x in self.unavailable if x not in other.unavailable
        ]

    def printme(self, showlists=False, stream=sys.stdout):
        """Print the content of the bag to `stream`."""
        self.to_be_installed.printme(
            banner="Packages to be installed:",
            indent="  ",
            showlists=showlists,
            stream=stream,
        )
        self.already_installed.printme(
            banner="Already installed packages:",
            indent="  ",
            showlists=showlists,
            stream=stream,
        )
        self.dependencies.printme(
            banner="Dependencies:",
            indent="  ",
            showlists=showlists,
            stream=stream,
            fltr=PackageFlags.is_not_weak,
        )
        self.dependencies.printme(
            banner="Weak dependencies:",
            indent="  ",
            showlists=showlists,
            stream=stream,
            fltr=PackageFlags.is_weak,
        )
        if len(self.unavailable) > 0:
            stream.write("Unavailable packages:\n")
            for pkg in self.unavailable:
                stream.write(f"  {pkg}\n")


class CliApp:
    """Command line interface."""

    __slots__ = ("__optparser",)

    def __init__(self):
        """Initialize the interface."""
        self.__optparser = self._make_optparser()

    @staticmethod
    def _make_optparser():
        """Make the option parser."""
        optparser = argparse.ArgumentParser(
            formatter_class=argparse.RawDescriptionHelpFormatter,
            description=__doc__,
            allow_abbrev=False,
        )
        optparser.add_argument(
            "--dnfopt",
            "-c",
            nargs=1,
            action="append",
            metavar="NAME[=VALUE]",
            dest="opts",
            help="dnf option",
        )
        commands = optparser.add_subparsers(title="commands")
        CliApp._add_showdeps(commands)
        CliApp._add_whatrequires(commands)
        return optparser

    @staticmethod
    def _add_showdeps(commands):
        """Register `showdeps` command."""
        cmdparser = commands.add_parser(
            "showdeps",
            help="show dependencies",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            description="Show dependencies for a given set of packages.",
            epilog=(
                "If --srpm is given, all provides from PACKAGES (except\n"
                "debuginfo and debugsource packages) are included to the\n"
                "list of packages to be installed. If --source is given,\n"
                "source repositories are additionally inspected, which\n"
                "means that also build requirements are included to the list\n"
                "of dependencies.\n"
                "\n"
                "Packages are displayed one per line, where fields are\n"
                "name, evr, arch, source_name, reponame, and flags,\n"
                "respectively. Flags have following meaning:\n"
                "\n"
                "    I - already installed\n"
                "    U - unavailable\n"
                "    R - require\n"
                "    B - build require\n"
                "    W - weak dependency\n"
                "    ? - both installed and unavailable (something is wrong)\n"
                "    _ - flag is not set\n"
                "\n"
                "What requires are tracked implicitly, which take a while.\n"
                "This can be disabled by --nowr switch. To see what requires\n"
                "particular packages, use --seewr seitch.\n"
                "\n"
                "To exclude dependencies that are already present in the\n"
                "distribution, use --exclude option followed either by a\n"
                "path to file or comma separated list (like in Ansible\n"
                "fashion). A file with dependencies to be excluded is a\n"
                "plain text file, following the following rules:\n"
                "\n"
                "    - each line contain a comma separated list of\n"
                "      dependencies that are merged in the one set\n"
                "    - if a line contains =, it is treated as an group\n"
                "      definition; a word before = is a group name; a comma\n"
                "      separated list of words is a group content\n"
                "    - groups are referenced in a list of dependencies as\n"
                "      @group; if a group was defined before, its content is\n"
                "      expanded; if not, it is passed to dnf\n"
                "    - if a comma separated list ends with comma, it\n"
                "      continues on the next line\n"
                "    - comments start with #\n"
                "    - redundant white spaces are stripped"
            ),
            allow_abbrev=False,
        )
        cmdparser.add_argument(
            "--srpm",
            action="store_true",
            dest="srpm",
            help="treat PACKAGES as source rpms",
        )
        cmdparser.add_argument(
            "--source",
            action="store_true",
            dest="source",
            help="inspect also source packages",
        )
        cmdparser.add_argument(
            "--nowr",
            action="store_false",
            dest="track_wr",
            help="disable what requires tracking",
        )
        cmdparser.add_argument(
            "--seewr",
            action="store_true",
            dest="show_wr",
            help="see what requires particular packages",
        )
        cmdparser.add_argument(
            "--exclude",
            "-x",
            nargs=1,
            action="store",
            metavar="CSV_OR_FILE",
            dest="xdeps",
            help="dependencies to be excluded",
        )
        cmdparser.add_argument(
            "pkg_spec", metavar="PACKAGES", nargs="+", help="package names"
        )
        cmdparser.set_defaults(command=CliApp.showdeps_cmd)

    @staticmethod
    def _add_whatrequires(commands):
        """Register `whatrequires` command."""
        cmdparser = commands.add_parser(
            "whatrequires",
            help="show what requires packages",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            description=(
                "Show what requires PACKAGES. If --srpm is given, this\n"
                "command prints what requires packages provided by PACKAGES\n"
                "source rpms."
            ),
            allow_abbrev=False,
        )
        cmdparser.add_argument(
            "--srpm",
            action="store_true",
            dest="srpm",
            help="treat PACKAGES as source rpms",
        )
        cmdparser.add_argument(
            "pkg_spec", metavar="PACKAGES", nargs="+", help="package names"
        )
        cmdparser.set_defaults(command=CliApp.whatrequires_cmd)

    @staticmethod
    def _read_excludes(xdeps):
        """Read dependencies to be excluded from `xdeps`."""
        if xdeps.find(",") >= 0:
            return csv2list(xdeps)
        with open(xdeps) as fobj:
            return xspec2list(fobj.read(), srcname=xdeps)

    @staticmethod
    def showdeps_cmd(args):
        """Implement `showdeps` command."""
        opts = opts2dict(args.opts or [])
        bag = Bag(opts)
        bag.install(args.pkg_spec, srpm=args.srpm, source=args.source)
        track_wr = args.track_wr and args.xdeps is None
        bag.resolve(track_wr=track_wr)
        if args.xdeps:
            pkg_spec = CliApp._read_excludes(args.xdeps[0])
            xbag = Bag(opts)
            xbag.install(pkg_spec, srpm=False, source=args.source)
            xbag.resolve(track_wr=False)
            bag.exclude(xbag)
            if args.track_wr:
                bag.track_what_requires()
        bag.printme(showlists=args.show_wr)
        return 0

    @staticmethod
    def whatrequires_cmd(args):
        """Implement `whatrequires` command."""
        opts = opts2dict(args.opts or [])
        bag = Bag(opts)
        packages = args.pkg_spec
        indent = ""
        if args.srpm:
            indent = "  "
            packages = bag._get_provides(packages)
            print("SRPMs content:")
            for pkg in sorted(packages):
                print(f"{indent}{pkg}")
            print("What requires us:")
        wrqs = []
        for pkg in packages:
            wrqs.extend(bag.what_requires(pkg, opts))
        wrqs = {x.name: x for x in wrqs}
        skeys = sorted(list(wrqs.keys()))
        for key in skeys:
            print(f"{indent}{Package(wrqs[key])}")

    def run(self, argv):
        """Run the cli application."""
        args = self.__optparser.parse_args(argv)
        return args.command(args)


if __name__ == "__main__":
    sys.exit(CliApp().run(sys.argv[1:]))
