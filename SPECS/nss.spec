%global nspr_build_version 4.35.0-1
%global nspr_release -1
%global nspr_version 4.35.0
%global nss_version 3.90.0
%global unsupported_tools_directory %{_libdir}/nss/unsupported-tools
%global saved_files_dir %{_libdir}/nss/saved
%global dracutlibdir %{_prefix}/lib/dracut
%global dracut_modules_dir %{dracutlibdir}/modules.d/05nss-softokn/
%global dracut_conf_dir %{dracutlibdir}/dracut.conf.d

# The timestamp of our downstream manual pages, e.g., nss-config.1
%global manual_date "Nov 13 2013"

%bcond_without tests

# Produce .chk files for the final stripped binaries
#
# NOTE: The LD_LIBRARY_PATH line guarantees shlibsign links
# against the freebl that we just built. This is necessary
# because the signing algorithm changed on 3.14 to DSA2 with SHA256
# whereas we previously signed with DSA and SHA1. We must Keep this line
# until all mock platforms have been updated.
# After %%{__os_install_post} we would add
# export LD_LIBRARY_PATH=$RPM_BUILD_ROOT/%%{_libdir}
%define __spec_install_post \
    %{?__debug_package:%{__debug_install_post}} \
    %{__arch_install_post} \
    %{__os_install_post} \
    $RPM_BUILD_ROOT/%{unsupported_tools_directory}/shlibsign -i $RPM_BUILD_ROOT/%{_libdir}/libsoftokn3.so \
    $RPM_BUILD_ROOT/%{unsupported_tools_directory}/shlibsign -i $RPM_BUILD_ROOT/%{_libdir}/libfreeblpriv3.so \
    $RPM_BUILD_ROOT/%{unsupported_tools_directory}/shlibsign -i $RPM_BUILD_ROOT/%{_libdir}/libfreebl3.so \
    $RPM_BUILD_ROOT/%{unsupported_tools_directory}/shlibsign -i $RPM_BUILD_ROOT/%{_libdir}/libnssdbm3.so \
%{nil}

# The upstream omits the trailing ".0", while we need it for
# consistency with the pkg-config version:
# https://bugzilla.redhat.com/show_bug.cgi?id=1578106
%{lua:
rpm.define(string.format("nss_archive_version %s",
           string.gsub(rpm.expand("%nss_version"), "(.*)%.0$", "%1")))
}

%{lua:
rpm.define(string.format("nss_release_tag NSS_%s_RTM",
           string.gsub(rpm.expand("%nss_archive_version"), "%.", "_")))
}

# This is taken from gnutls.spec
%define srpmhash() %{lua:
local files = rpm.expand("%_specdir/nss.spec")
for i, p in ipairs(patches) do
   files = files.." "..p
end
for i, p in ipairs(sources) do
   files = files.." "..p
end
local sha256sum = assert(io.popen("cat "..files.."| sha256sum"))
local hash = sha256sum:read("*a")
sha256sum:close()
print(string.sub(hash, 0, 16))
}

Summary:          Network Security Services
Name:             nss
Version:          %{nss_version}
Release:          6%{?dist}
License:          MPLv2.0
URL:              http://www.mozilla.org/projects/security/pki/nss/
Requires:         nspr >= %{nspr_version}%{nspr_release}
Requires:         nss-util >= %{nss_version}
# TODO: revert to same version as nss once we are done with the merge
Requires:         nss-softokn%{_isa} >= %{nss_version}
Requires:         nss-system-init
Requires:         p11-kit-trust
Requires:         /usr/bin/update-crypto-policies
BuildRequires:    nspr-devel >= %{nspr_build_version}
# for shlibsign
BuildRequires:    nss-softokn
BuildRequires:    sqlite-devel
BuildRequires:    zlib-devel
BuildRequires:    pkgconfig
BuildRequires:    gawk
BuildRequires:    psmisc
BuildRequires:    perl-interpreter
BuildRequires:    gcc-c++

Source0:          https://ftp.mozilla.org/pub/security/nss/releases/%{nss_release_tag}/src/%{name}-%{nss_archive_version}.tar.gz
Source1:          nss-util.pc.in
Source2:          nss-util-config.in
Source3:          nss-softokn.pc.in
Source4:          nss-softokn-config.in
Source6:          nss-softokn-dracut-module-setup.sh
Source7:          nss-softokn-dracut.conf
Source8:          nss.pc.in
Source9:          nss-config.in
Source10:         blank-cert8.db
Source11:         blank-key3.db
Source12:         blank-secmod.db
Source13:         blank-cert9.db
Source14:         blank-key4.db
Source15:         system-pkcs11.txt
Source16:         setup-nsssysinit.sh
Source20:         nss-config.xml
Source21:         setup-nsssysinit.xml
Source22:         pkcs11.txt.xml
Source23:         cert8.db.xml
Source24:         cert9.db.xml
Source25:         key3.db.xml
Source26:         key4.db.xml
Source27:         secmod.db.xml
Source28:         nss-p11-kit.config
# fips algorithms are tied to the red hat validation, others
# will have their own validation
Source30:         fips_algorithms.h

Source50:         NameConstraints_Certs.tar

# To inject hardening flags for DSO
Patch1:           nss-dso-ldflags.patch
# This patch uses the GCC -iquote option documented at
# http://gcc.gnu.org/onlinedocs/gcc/Directory-Options.html#Directory-Options
# to give the in-tree headers a higher priority over the system headers,
# when they are included through the quote form (#include "file.h").
#
# This ensures a build even when system headers are older. Such is the
# case when starting an update with API changes or even private export
# changes.
#
# Once the buildroot aha been bootstrapped the patch may be removed
# but it doesn't hurt to keep it.
Patch4:           iquote.patch
# To revert the change in:
# https://bugzilla.mozilla.org/show_bug.cgi?id=818686
Patch9:		  nss-sysinit-userdb.patch
# Disable nss-sysinit test which is solely to test the above change
Patch10:          nss-skip-sysinit-gtests.patch
Patch15:          nss-3.90-extend-db-dump-time.patch
# For compatibility reasons, we stick with the old PKCS #11 2.40
# definition of CK_GCM_PARAMS:
%if 0%{?fedora} < 34
%if 0%{?rhel} < 9
Patch20:          nss-gcm-param-default-pkcs11v2.patch
%endif
%endif
# Local patch: disable MD5 (also MD2 and MD4) completely
# https://bugzilla.redhat.com/show_bug.cgi?id=1849938
Patch25:          nss-disable-md5.patch
# Local patch for TLS_ECDHE_{ECDSA|RSA}_WITH_3DES_EDE_CBC_SHA ciphers
Patch30:          rhbz1185708-enable-ecc-3des-ciphers-by-default.patch
Patch34:          nss-3.71-fix-lto-gtests.patch
# Local patch: disable Delegated Credentials
Patch35:	  nss-disable-dc.patch
# Local patch: ignore rsa, rsa-pss, ecdsa policies until crypto-policies
# is updated.
Patch40:          nss-3.66-disable-signature-policies.patch
# Local patch: disable tests that require external reference so brew completes
Patch45:          nss-3.66-disable-external-host-test.patch
# Local patch: restore old pkcs 12 defaults on old version of rhel
Patch50:          nss-3.66-restore-old-pkcs12-default.patch
# Local Patch: restore expired distrusted certs for now
Patch51:          nss-3.79-revert-distrusted-certs.patch
# Local Patch: update fipsdefaults to AES
Patch52:          nss-3.79-pkcs12-fips-defaults.patch
Patch53:          nss-3.71-camellia-pkcs12-doc.patch
Patch54:          nss-3.90-disable-ech.patch

# https://bugzilla.redhat.com/show_bug.cgi?id=1774659
Patch57:          nss-3.79-dbtool.patch
Patch58:          nss-3.79-fips.patch
# https://bugzilla.mozilla.org/show_bug.cgi?id=1836781
# https://bugzilla.mozilla.org/show_bug.cgi?id=1836925
Patch60:          nss-3.90-DisablingASM.patch
Patch61:          nss-3.79-fips-review.patches
Patch62:          nss-3.90-no-dbm-25519.patch
Patch63:          nss-3.90-pbkdf2-indicator.patch

#ems policy. needs to upstream
Patch70:          nss-3.90-add-ems-policy.patch

Patch80:         blinding_ct.patch
Patch81:         nss-3.90-fips-pkcs11-long-hash.patch
Patch82:         nss-3.90-fips-safe-memset.patch
Patch83:         nss-3.90-fips-indicators.patch
Patch84:         nss-3.90-aes-gmc-indicator.patch
Patch85:         nss-3.90-fips-indicators2.patch
Patch86:         nss-3.90-dh-test-update.patch
Patch90:         nss_p256_scalar_validated.patch
Patch91:         nss_p384_scalar_validated.patch
Patch92:         nss_p384_hacl.patch
Patch93:         nss_p521_hacl.patch
Patch94:         nss-3.90-ecc-wrap-fix.patch

%description
Network Security Services (NSS) is a set of libraries designed to
support cross-platform development of security-enabled client and
server applications. Applications built with NSS can support SSL v2
and v3, TLS, PKCS #5, PKCS #7, PKCS #11, PKCS #12, S/MIME, X.509
v3 certificates, and other security standards.

%package tools
Summary:          Tools for the Network Security Services
Requires:         %{name}%{?_isa} = %{version}-%{release}

%description tools
Network Security Services (NSS) is a set of libraries designed to
support cross-platform development of security-enabled client and
server applications. Applications built with NSS can support SSL v2
and v3, TLS, PKCS #5, PKCS #7, PKCS #11, PKCS #12, S/MIME, X.509
v3 certificates, and other security standards.

Install the nss-tools package if you need command-line tools to
manipulate the NSS certificate and key database.

%package sysinit
Summary:          System NSS Initialization
# providing nss-system-init without version so that it can
# be replaced by a better one, e.g. supplied by the os vendor
Provides:         nss-system-init
Requires:         nss%{?_isa} = %{version}-%{release}
Requires(post):   coreutils, sed

%description sysinit
Default Operating System module that manages applications loading
NSS globally on the system. This module loads the system defined
PKCS #11 modules for NSS and chains with other NSS modules to load
any system or user configured modules.

%package devel
Summary:          Development libraries for Network Security Services
Provides:         nss-static = %{version}-%{release}
Requires:         nss%{?_isa} = %{version}-%{release}
Requires:         nss-util-devel
Requires:         nss-softokn-devel
Requires:         nspr-devel >= %{nspr_version}%{nspr_release}
Requires:         pkgconfig
BuildRequires:    xmlto

%description devel
Header and Library files for doing development with Network Security Services.


%package pkcs11-devel
Summary:          Development libraries for PKCS #11 (Cryptoki) using NSS
Provides:         nss-pkcs11-devel-static = %{version}-%{release}
Requires:         nss-devel = %{version}-%{release}
Requires:         nss-softokn-freebl-devel = %{version}-%{release}

%description pkcs11-devel
Library files for developing PKCS #11 modules using basic NSS
low level services.


%package util
Summary:          Network Security Services Utilities Library
Requires:         nspr >= %{nspr_version}%{nspr_release}

%description util
Utilities for Network Security Services and the Softoken module

%package util-devel
Summary:          Development libraries for Network Security Services Utilities
Requires:         nss-util%{?_isa} = %{version}-%{release}
Requires:         nspr-devel >= %{nspr_version}%{nspr_release}
Requires:         pkgconfig

%description util-devel
Header and library files for doing development with Network Security Services.


%package softokn
Summary:          Network Security Services Softoken Module
Requires:         nspr >= %{nspr_version}%{nspr_release}
Requires:         nss-util >= %{version}-%{release}
Requires:         nss-softokn-freebl%{_isa} >= %{version}-%{release}

%description softokn
Network Security Services Softoken Cryptographic Module

%package softokn-freebl
Summary:          Freebl library for the Network Security Services
# For PR_GetEnvSecure() from nspr >= 4.12
Requires:         nspr >= 4.12
# For NSS_SecureMemcmpZero() from nss-util >= 3.33
Requires:         nss-util >= 3.33
Conflicts:        nss < 3.12.2.99.3-5
Conflicts:        filesystem < 3

%description softokn-freebl
NSS Softoken Cryptographic Module Freebl Library

Install the nss-softokn-freebl package if you need the freebl library.

%package softokn-freebl-devel
Summary:          Header and Library files for doing development with the Freebl library for NSS
Provides:         nss-softokn-freebl-static = %{version}-%{release}
Requires:         nss-softokn-freebl%{?_isa} = %{version}-%{release}

%description softokn-freebl-devel
NSS Softoken Cryptographic Module Freebl Library Development Tools
This package supports special needs of some PKCS #11 module developers and
is otherwise considered private to NSS. As such, the programming interfaces
may change and the usual NSS binary compatibility commitments do not apply.
Developers should rely only on the officially supported NSS public API.

%package softokn-devel
Summary:          Development libraries for Network Security Services
Requires:         nss-softokn%{?_isa} = %{version}-%{release}
Requires:         nss-softokn-freebl-devel%{?_isa} = %{version}-%{release}
Requires:         nspr-devel >= %{nspr_version}%{nspr_release}
Requires:         nss-util-devel >= %{version}-%{release}
Requires:         pkgconfig
BuildRequires:    nspr-devel >= %{nspr_build_version}

%description softokn-devel
Header and library files for doing development with Network Security Services.


%prep
%autosetup -N -n %{name}-%{nss_archive_version}
pushd nss
%autopatch -p1 
popd

# copy the fips_algorithms.h for this release
# this file is release specific and matches what
# each vendors claim in their own FIPS certification
cp %{SOURCE30} nss/lib/softoken/

#update expired test certs
pushd nss
tar xvf %{SOURCE50}
popd

# https://bugzilla.redhat.com/show_bug.cgi?id=1247353
find nss/lib/libpkix -perm /u+x -type f -exec chmod -x {} \;

%build

export FREEBL_NO_DEPEND=1

# Must export FREEBL_LOWHASH=1 for nsslowhash.h so that it gets
# copied to dist and the rpm install phase can find it
# This due of the upstream changes to fix
# https://bugzilla.mozilla.org/show_bug.cgi?id=717906
export FREEBL_LOWHASH=1

# uncomment if the iquote patch is activated
export IN_TREE_FREEBL_HEADERS_FIRST=1

# FIPS related defines
export NSS_FORCE_FIPS=1
export NSS_FIPS_VERSION="%{name}\ %{version}-%{srpmhash}"
eval $(sed -n 's/^\(\(NAME\|VERSION_ID\)=.*\)/OS_\1/p' /etc/os-release | sed -e 's/ /\\ /g')
export FIPS_MODULE_OS="$OS_NAME\ ${OS_VERSION_ID%%.*}"
export NSS_FIPS_MODULE_ID="${FIPS_MODULE_OS}\ ${NSS_FIPS_VERSION}"
export NSS_FIPS_140_3=1
export NSS_ENABLE_FIPS_INDICATORS=1

# Enable compiler optimizations and disable debugging code
export BUILD_OPT=1

# Uncomment to disable optimizations
#RPM_OPT_FLAGS=`echo $RPM_OPT_FLAGS | sed -e 's/-O2/-O0/g'`
#export RPM_OPT_FLAGS

# Generate symbolic info for debuggers
export XCFLAGS=$RPM_OPT_FLAGS

export LDFLAGS=$RPM_LD_FLAGS

export DSO_LDFLAGS=$RPM_LD_FLAGS

export PKG_CONFIG_ALLOW_SYSTEM_LIBS=1
export PKG_CONFIG_ALLOW_SYSTEM_CFLAGS=1

export NSPR_INCLUDE_DIR=`/usr/bin/pkg-config --cflags-only-I nspr | sed 's/-I//'`
export NSPR_LIB_DIR=%{_libdir}

export NSS_USE_SYSTEM_SQLITE=1

export NSS_ALLOW_SSLKEYLOGFILE=1

export NSS_SEED_ONLY_DEV_URANDOM=1

%ifnarch noarch
%if 0%{__isa_bits} == 64
export USE_64=1
%endif
%endif

# Set the policy file location
# if set NSS will always check for the policy file and load if it exists
export POLICY_FILE="nss.config"
# location of the policy file
export POLICY_PATH="/etc/crypto-policies/back-ends"

%{__make} -C ./nss all
%{__make} -C ./nss latest

# build the man pages clean
pushd ./nss/doc
rm -rf ./nroff
make clean
echo -n %{manual_date} > date.xml
echo -n %{version} > version.xml
make
popd

# and copy them to the dist directory for %%install to find them
mkdir -p ./dist/docs/nroff
cp ./nss/doc/nroff/* ./dist/docs/nroff

# Set up our package files
mkdir -p ./dist/pkgconfig

cat %{SOURCE1} | sed -e "s,%%libdir%%,%{_libdir},g" \
                          -e "s,%%prefix%%,%{_prefix},g" \
                          -e "s,%%exec_prefix%%,%{_prefix},g" \
                          -e "s,%%includedir%%,%{_includedir}/nss3,g" \
                          -e "s,%%NSPR_VERSION%%,%{nspr_version},g" \
                          -e "s,%%NSSUTIL_VERSION%%,%{version},g" > \
                          ./dist/pkgconfig/nss-util.pc

NSSUTIL_VMAJOR=`cat nss/lib/util/nssutil.h | grep "#define.*NSSUTIL_VMAJOR" | awk '{print $3}'`
NSSUTIL_VMINOR=`cat nss/lib/util/nssutil.h | grep "#define.*NSSUTIL_VMINOR" | awk '{print $3}'`
NSSUTIL_VPATCH=`cat nss/lib/util/nssutil.h | grep "#define.*NSSUTIL_VPATCH" | awk '{print $3}'`

cat %{SOURCE2} | sed -e "s,@libdir@,%{_libdir},g" \
                          -e "s,@prefix@,%{_prefix},g" \
                          -e "s,@exec_prefix@,%{_prefix},g" \
                          -e "s,@includedir@,%{_includedir}/nss3,g" \
                          -e "s,@MOD_MAJOR_VERSION@,$NSSUTIL_VMAJOR,g" \
                          -e "s,@MOD_MINOR_VERSION@,$NSSUTIL_VMINOR,g" \
                          -e "s,@MOD_PATCH_VERSION@,$NSSUTIL_VPATCH,g" \
                          > ./dist/pkgconfig/nss-util-config

chmod 755 ./dist/pkgconfig/nss-util-config

cat %{SOURCE3} | sed -e "s,%%libdir%%,%{_libdir},g" \
                          -e "s,%%prefix%%,%{_prefix},g" \
                          -e "s,%%exec_prefix%%,%{_prefix},g" \
                          -e "s,%%includedir%%,%{_includedir}/nss3,g" \
                          -e "s,%%NSPR_VERSION%%,%{nspr_version},g" \
                          -e "s,%%NSSUTIL_VERSION%%,%{nss_version},g" \
                          -e "s,%%SOFTOKEN_VERSION%%,%{version},g" > \
                          ./dist/pkgconfig/nss-softokn.pc

SOFTOKEN_VMAJOR=`cat nss/lib/softoken/softkver.h | grep "#define.*SOFTOKEN_VMAJOR" | awk '{print $3}'`
SOFTOKEN_VMINOR=`cat nss/lib/softoken/softkver.h | grep "#define.*SOFTOKEN_VMINOR" | awk '{print $3}'`
SOFTOKEN_VPATCH=`cat nss/lib/softoken/softkver.h | grep "#define.*SOFTOKEN_VPATCH" | awk '{print $3}'`

cat %{SOURCE4} | sed -e "s,@libdir@,%{_libdir},g" \
                          -e "s,@prefix@,%{_prefix},g" \
                          -e "s,@exec_prefix@,%{_prefix},g" \
                          -e "s,@includedir@,%{_includedir}/nss3,g" \
                          -e "s,@MOD_MAJOR_VERSION@,$SOFTOKEN_VMAJOR,g" \
                          -e "s,@MOD_MINOR_VERSION@,$SOFTOKEN_VMINOR,g" \
                          -e "s,@MOD_PATCH_VERSION@,$SOFTOKEN_VPATCH,g" \
                          > ./dist/pkgconfig/nss-softokn-config

chmod 755 ./dist/pkgconfig/nss-softokn-config

cat %{SOURCE8} | sed -e "s,%%libdir%%,%{_libdir},g" \
                          -e "s,%%prefix%%,%{_prefix},g" \
                          -e "s,%%exec_prefix%%,%{_prefix},g" \
                          -e "s,%%includedir%%,%{_includedir}/nss3,g" \
                          -e "s,%%NSS_VERSION%%,%{version},g" \
                          -e "s,%%NSPR_VERSION%%,%{nspr_version},g" \
                          -e "s,%%NSSUTIL_VERSION%%,%{nss_version},g" \
                          -e "s,%%SOFTOKEN_VERSION%%,%{nss_version},g" > \
                          ./dist/pkgconfig/nss.pc

NSS_VMAJOR=`cat nss/lib/nss/nss.h | grep "#define.*NSS_VMAJOR" | awk '{print $3}'`
NSS_VMINOR=`cat nss/lib/nss/nss.h | grep "#define.*NSS_VMINOR" | awk '{print $3}'`
NSS_VPATCH=`cat nss/lib/nss/nss.h | grep "#define.*NSS_VPATCH" | awk '{print $3}'`

cat %{SOURCE9} | sed -e "s,@libdir@,%{_libdir},g" \
                          -e "s,@prefix@,%{_prefix},g" \
                          -e "s,@exec_prefix@,%{_prefix},g" \
                          -e "s,@includedir@,%{_includedir}/nss3,g" \
                          -e "s,@MOD_MAJOR_VERSION@,$NSS_VMAJOR,g" \
                          -e "s,@MOD_MINOR_VERSION@,$NSS_VMINOR,g" \
                          -e "s,@MOD_PATCH_VERSION@,$NSS_VPATCH,g" \
                          > ./dist/pkgconfig/nss-config

chmod 755 ./dist/pkgconfig/nss-config

cat %{SOURCE16} > ./dist/pkgconfig/setup-nsssysinit.sh
chmod 755 ./dist/pkgconfig/setup-nsssysinit.sh

cp ./nss/lib/ckfw/nssck.api ./dist/private/nss/

date +"%e %B %Y" | tr -d '\n' > date.xml
echo -n %{version} > version.xml

# configuration files and setup script
for m in %{SOURCE20} %{SOURCE21} %{SOURCE22}; do
  cp ${m} .
done
for m in nss-config.xml setup-nsssysinit.xml pkcs11.txt.xml; do
  xmlto man ${m}
done

# nss databases considered to be configuration files
for m in %{SOURCE23} %{SOURCE24} %{SOURCE25} %{SOURCE26} %{SOURCE27}; do
  cp ${m} .
done
for m in cert8.db.xml cert9.db.xml key3.db.xml key4.db.xml secmod.db.xml; do
  xmlto man ${m}
done


%check
%if %{with tests}
# Begin -- copied from the build section

export FREEBL_NO_DEPEND=1

export BUILD_OPT=1

%ifnarch noarch
%if 0%{__isa_bits} == 64
export USE_64=1
%endif
%endif

# End -- copied from the build section

# This is necessary because the test suite tests algorithms that are
# disabled by the system policy.
export NSS_IGNORE_SYSTEM_POLICY=1

%ifarch i686 ppcle64
export NSS_DB_DUMP_TIME=10
%endif

# enable the following line to force a test failure
# find ./nss -name \*.chk | xargs rm -f

# Run test suite.
# In order to support multiple concurrent executions of the test suite
# (caused by concurrent RPM builds) on a single host,
# we'll use a random port. Also, we want to clean up any stuck
# selfserv processes. If process name "selfserv" is used everywhere,
# we can't simply do a "killall selfserv", because it could disturb
# concurrent builds. Therefore we'll do a search and replace and use
# a different process name.
# Using xargs doesn't mix well with spaces in filenames, in order to
# avoid weird quoting we'll require that no spaces are being used.

SPACEISBAD=`find ./nss/tests | grep -c ' '` ||:
if [ $SPACEISBAD -ne 0 ]; then
  echo "error: filenames containing space are not supported (xargs)"
  exit 1
fi
MYRAND=`perl -e 'print 9000 + int rand 1000'`; echo $MYRAND ||:
RANDSERV=selfserv_${MYRAND}; echo $RANDSERV ||:
DISTBINDIR=`ls -d ./dist/*.OBJ/bin`; echo $DISTBINDIR ||:
pushd "$DISTBINDIR"
ln -s selfserv $RANDSERV
popd
# man perlrun, man perlrequick
# replace word-occurrences of selfserv with selfserv_$MYRAND
find ./nss/tests -type f |\
  grep -v "\.db$" |grep -v "\.crl$" | grep -v "\.crt$" |\
  grep -vw CVS  |xargs grep -lw selfserv |\
  xargs -l perl -pi -e "s/\bselfserv\b/$RANDSERV/g" ||:

killall $RANDSERV || :

rm -rf ./tests_results
pushd nss/tests
# all.sh is the test suite script

#  don't need to run all the tests when testing packaging
export NSS_DEFAULT_DB_TYPE=dbm  #in RHEL 8, the default db is sql, but we want
                                # standard to test dbm, or upgradedb will fail
%define nss_cycles "standard pkix upgradedb sharedb threadunsafe"
#  the full list from all.sh is:
#  "cipher lowhash libpkix cert dbtests tools fips sdr crmf smime ssl ocsp merge pkits chains ec gtests ssl_gtests"
%define nss_tests "libpkix cert dbtests tools fips sdr crmf smime ssl ocsp merge pkits chains ec gtests ssl_gtests"
#  nss_ssl_tests: crl bypass_normal normal_bypass normal_fips fips_normal iopr policy
#  nss_ssl_run: cov auth stapling stress
#
# Uncomment these lines if you need to temporarily
# disable some test suites for faster test builds
# % define nss_ssl_tests "normal_fips"
# % define nss_ssl_run "cov"

HOST=localhost DOMSUF=localdomain PORT=$MYRAND NSS_CYCLES=%{?nss_cycles} NSS_TESTS=%{?nss_tests} NSS_SSL_TESTS=%{?nss_ssl_tests} NSS_SSL_RUN=%{?nss_ssl_run} ./all.sh
popd

%endif

%install

# There is no make install target so we'll do it ourselves.

mkdir -p $RPM_BUILD_ROOT/%{_includedir}/nss3
mkdir -p $RPM_BUILD_ROOT/%{_includedir}/nss3/templates
mkdir -p $RPM_BUILD_ROOT/%{_bindir}
mkdir -p $RPM_BUILD_ROOT/%{_libdir}
mkdir -p $RPM_BUILD_ROOT/%{unsupported_tools_directory}
mkdir -p $RPM_BUILD_ROOT/%{_libdir}/pkgconfig
mkdir -p $RPM_BUILD_ROOT/%{saved_files_dir}
mkdir -p $RPM_BUILD_ROOT/%{dracut_modules_dir}
mkdir -p $RPM_BUILD_ROOT/%{dracut_conf_dir}
mkdir -p $RPM_BUILD_ROOT/%{_sysconfdir}/crypto-policies/local.d
%if %{defined rhel}
# not needed for rhel and its derivatives only fedora
%else
# because of the pp.1 conflict with perl-PAR-Packer
mkdir -p $RPM_BUILD_ROOT%{_datadir}/doc/nss-tools
%endif

install -m 755 %{SOURCE6} $RPM_BUILD_ROOT/%{dracut_modules_dir}/module-setup.sh
install -m 644 %{SOURCE7} $RPM_BUILD_ROOT/%{dracut_conf_dir}/50-nss-softokn.conf

mkdir -p $RPM_BUILD_ROOT%{_mandir}/man1
mkdir -p $RPM_BUILD_ROOT%{_mandir}/man5

# Copy the binary libraries we want
for file in libnssutil3.so libsoftokn3.so libnssdbm3.so libfreebl3.so libfreeblpriv3.so libnss3.so libnsssysinit.so libsmime3.so libssl3.so
do
  install -p -m 755 dist/*.OBJ/lib/$file $RPM_BUILD_ROOT/%{_libdir}
done

# Install the empty NSS db files
# Legacy db
mkdir -p $RPM_BUILD_ROOT/%{_sysconfdir}/pki/nssdb
install -p -m 644 %{SOURCE10} $RPM_BUILD_ROOT/%{_sysconfdir}/pki/nssdb/cert8.db
install -p -m 644 %{SOURCE11} $RPM_BUILD_ROOT/%{_sysconfdir}/pki/nssdb/key3.db
install -p -m 644 %{SOURCE12} $RPM_BUILD_ROOT/%{_sysconfdir}/pki/nssdb/secmod.db
# Shared db
install -p -m 644 %{SOURCE13} $RPM_BUILD_ROOT/%{_sysconfdir}/pki/nssdb/cert9.db
install -p -m 644 %{SOURCE14} $RPM_BUILD_ROOT/%{_sysconfdir}/pki/nssdb/key4.db
install -p -m 644 %{SOURCE15} $RPM_BUILD_ROOT/%{_sysconfdir}/pki/nssdb/pkcs11.txt

# Copy the development libraries we want
for file in libcrmf.a libnssb.a libnssckfw.a
do
  install -p -m 644 dist/*.OBJ/lib/$file $RPM_BUILD_ROOT/%{_libdir}
done

# Copy the binaries we want
for file in certutil cmsutil crlutil modutil nss-policy-check pk12util signver ssltap
do
  install -p -m 755 dist/*.OBJ/bin/$file $RPM_BUILD_ROOT/%{_bindir}
done

# Copy the binaries we ship as unsupported
for file in bltest dbtool ecperf fbectest fipstest shlibsign atob btoa derdump listsuites ocspclnt pp selfserv signtool strsclnt symkeyutil tstclnt validation vfyserv vfychain
do
  install -p -m 755 dist/*.OBJ/bin/$file $RPM_BUILD_ROOT/%{unsupported_tools_directory}
done

# Copy the include files we want
for file in dist/public/nss/*.h
do
  install -p -m 644 $file $RPM_BUILD_ROOT/%{_includedir}/nss3
done

# Copy some freebl include files we also want
for file in blapi.h alghmac.h cmac.h
do
  install -p -m 644 dist/private/nss/$file $RPM_BUILD_ROOT/%{_includedir}/nss3
done

# Copy the static freebl library
for file in libfreebl.a
do
install -p -m 644 dist/*.OBJ/lib/$file $RPM_BUILD_ROOT/%{_libdir}
done

# Copy the template files we want
for file in dist/private/nss/templates.c dist/private/nss/nssck.api
do
  install -p -m 644 $file $RPM_BUILD_ROOT/%{_includedir}/nss3/templates
done

# Copy the package configuration files
install -p -m 644 ./dist/pkgconfig/nss-util.pc $RPM_BUILD_ROOT/%{_libdir}/pkgconfig/nss-util.pc
install -p -m 755 ./dist/pkgconfig/nss-util-config $RPM_BUILD_ROOT/%{_bindir}/nss-util-config
install -p -m 644 ./dist/pkgconfig/nss-softokn.pc $RPM_BUILD_ROOT/%{_libdir}/pkgconfig/nss-softokn.pc
install -p -m 755 ./dist/pkgconfig/nss-softokn-config $RPM_BUILD_ROOT/%{_bindir}/nss-softokn-config
install -p -m 644 ./dist/pkgconfig/nss.pc $RPM_BUILD_ROOT/%{_libdir}/pkgconfig/nss.pc
install -p -m 755 ./dist/pkgconfig/nss-config $RPM_BUILD_ROOT/%{_bindir}/nss-config
# Copy the pkcs #11 configuration script
install -p -m 755 ./dist/pkgconfig/setup-nsssysinit.sh $RPM_BUILD_ROOT/%{_bindir}/setup-nsssysinit.sh
# install a symbolic link to it, without the ".sh" suffix,
# that matches the man page documentation
ln -r -s -f $RPM_BUILD_ROOT/%{_bindir}/setup-nsssysinit.sh $RPM_BUILD_ROOT/%{_bindir}/setup-nsssysinit

# Copy the man pages for scripts
for f in nss-config setup-nsssysinit; do
   install -c -m 644 ${f}.1 $RPM_BUILD_ROOT%{_mandir}/man1/${f}.1
done
# Copy the man pages for the nss tools
for f in certutil cmsutil crlutil derdump modutil nss-policy-check pk12util signtool signver ssltap vfychain vfyserv; do
  install -c -m 644 ./dist/docs/nroff/${f}.1 $RPM_BUILD_ROOT%{_mandir}/man1/${f}.1
done
%if %{defined rhel}
install -c -m 644 ./dist/docs/nroff/pp.1 $RPM_BUILD_ROOT%{_mandir}/man1/pp.1
%else
install -c -m 644 ./dist/docs/nroff/pp.1 $RPM_BUILD_ROOT%{_datadir}/doc/nss-tools/pp.1
%endif

# Copy the man pages for the configuration files
for f in pkcs11.txt; do
   install -c -m 644 ${f}.5 $RPM_BUILD_ROOT%{_mandir}/man5/${f}.5
done
# Copy the man pages for the nss databases
for f in cert8.db cert9.db key3.db key4.db secmod.db; do
   install -c -m 644 ${f}.5 $RPM_BUILD_ROOT%{_mandir}/man5/${f}.5
done

# Copy the crypto-policies configuration file
install -p -m 644 %{SOURCE28} $RPM_BUILD_ROOT/%{_sysconfdir}/crypto-policies/local.d

%triggerpostun -n nss-sysinit -- nss-sysinit < 3.12.8-3
# Reverse unwanted disabling of sysinit by faulty preun sysinit scriplet
# from previous versions of nss.spec
/usr/bin/setup-nsssysinit.sh on

%posttrans
update-crypto-policies --no-reload &> /dev/null || :


%files
%{!?_licensedir:%global license %%doc}
%license nss/COPYING
%{_libdir}/libnss3.so
%{_libdir}/libssl3.so
%{_libdir}/libsmime3.so
%dir %{_sysconfdir}/pki/nssdb
%config(noreplace) %verify(not md5 size mtime) %{_sysconfdir}/pki/nssdb/cert8.db
%config(noreplace) %verify(not md5 size mtime) %{_sysconfdir}/pki/nssdb/key3.db
%config(noreplace) %verify(not md5 size mtime) %{_sysconfdir}/pki/nssdb/secmod.db
%config(noreplace) %verify(not md5 size mtime) %{_sysconfdir}/pki/nssdb/cert9.db
%config(noreplace) %verify(not md5 size mtime) %{_sysconfdir}/pki/nssdb/key4.db
%config(noreplace) %verify(not md5 size mtime) %{_sysconfdir}/pki/nssdb/pkcs11.txt
%config(noreplace) %verify(not md5 size mtime) %{_sysconfdir}/crypto-policies/local.d/nss-p11-kit.config
%doc %{_mandir}/man5/cert8.db.5*
%doc %{_mandir}/man5/key3.db.5*
%doc %{_mandir}/man5/secmod.db.5*
%doc %{_mandir}/man5/cert9.db.5*
%doc %{_mandir}/man5/key4.db.5*
%doc %{_mandir}/man5/pkcs11.txt.5*

%files sysinit
%{_libdir}/libnsssysinit.so
%{_bindir}/setup-nsssysinit.sh
# symbolic link to setup-nsssysinit.sh
%{_bindir}/setup-nsssysinit
%doc %{_mandir}/man1/setup-nsssysinit.1*

%files tools
%{_bindir}/certutil
%{_bindir}/cmsutil
%{_bindir}/crlutil
%{_bindir}/modutil
%{_bindir}/nss-policy-check
%{_bindir}/pk12util
%{_bindir}/signver
%{_bindir}/ssltap
%{unsupported_tools_directory}/atob
%{unsupported_tools_directory}/btoa
%{unsupported_tools_directory}/derdump
%{unsupported_tools_directory}/listsuites
%{unsupported_tools_directory}/ocspclnt
%{unsupported_tools_directory}/pp
%{unsupported_tools_directory}/selfserv
%{unsupported_tools_directory}/signtool
%{unsupported_tools_directory}/strsclnt
%{unsupported_tools_directory}/symkeyutil
%{unsupported_tools_directory}/tstclnt
%{unsupported_tools_directory}/validation
%{unsupported_tools_directory}/vfyserv
%{unsupported_tools_directory}/vfychain
# instead of %%{_mandir}/man*/* let's list them explicitly
# supported tools
%doc %{_mandir}/man1/certutil.1*
%doc %{_mandir}/man1/cmsutil.1*
%doc %{_mandir}/man1/crlutil.1*
%doc %{_mandir}/man1/modutil.1*
%doc %{_mandir}/man1/nss-policy-check.1*
%doc %{_mandir}/man1/pk12util.1*
%doc %{_mandir}/man1/signver.1*
# unsupported tools
%doc %{_mandir}/man1/derdump.1*
%doc %{_mandir}/man1/signtool.1*
%if %{defined rhel}
%doc %{_mandir}/man1/pp.1*
%else
%dir %{_datadir}/doc/nss-tools
%doc %{_datadir}/doc/nss-tools/pp.1
%endif
%doc %{_mandir}/man1/ssltap.1*
%doc %{_mandir}/man1/vfychain.1*
%doc %{_mandir}/man1/vfyserv.1*

%files devel
%{_libdir}/libcrmf.a
%{_libdir}/pkgconfig/nss.pc
%{_bindir}/nss-config
%doc %{_mandir}/man1/nss-config.1*

%dir %{_includedir}/nss3
%{_includedir}/nss3/cert.h
%{_includedir}/nss3/certdb.h
%{_includedir}/nss3/certt.h
%{_includedir}/nss3/cmmf.h
%{_includedir}/nss3/cmmft.h
%{_includedir}/nss3/cms.h
%{_includedir}/nss3/cmsreclist.h
%{_includedir}/nss3/cmst.h
%{_includedir}/nss3/crmf.h
%{_includedir}/nss3/crmft.h
%{_includedir}/nss3/cryptohi.h
%{_includedir}/nss3/cryptoht.h
%{_includedir}/nss3/sechash.h
%{_includedir}/nss3/jar-ds.h
%{_includedir}/nss3/jar.h
%{_includedir}/nss3/jarfile.h
%{_includedir}/nss3/key.h
%{_includedir}/nss3/keyhi.h
%{_includedir}/nss3/keyt.h
%{_includedir}/nss3/keythi.h
%{_includedir}/nss3/nss.h
%{_includedir}/nss3/nssckbi.h
%{_includedir}/nss3/ocsp.h
%{_includedir}/nss3/ocspt.h
%{_includedir}/nss3/p12.h
%{_includedir}/nss3/p12plcy.h
%{_includedir}/nss3/p12t.h
%{_includedir}/nss3/pk11func.h
%{_includedir}/nss3/pk11hpke.h
%{_includedir}/nss3/pk11pqg.h
%{_includedir}/nss3/pk11priv.h
%{_includedir}/nss3/pk11pub.h
%{_includedir}/nss3/pk11sdr.h
%{_includedir}/nss3/pkcs12.h
%{_includedir}/nss3/pkcs12t.h
%{_includedir}/nss3/pkcs7t.h
%{_includedir}/nss3/preenc.h
%{_includedir}/nss3/secmime.h
%{_includedir}/nss3/secmod.h
%{_includedir}/nss3/secmodt.h
%{_includedir}/nss3/secpkcs5.h
%{_includedir}/nss3/secpkcs7.h
%{_includedir}/nss3/smime.h
%{_includedir}/nss3/ssl.h
%{_includedir}/nss3/sslerr.h
%{_includedir}/nss3/sslexp.h
%{_includedir}/nss3/sslproto.h
%{_includedir}/nss3/sslt.h

%files pkcs11-devel
%{_includedir}/nss3/nssbase.h
%{_includedir}/nss3/nssbaset.h
%{_includedir}/nss3/nssckepv.h
%{_includedir}/nss3/nssckft.h
%{_includedir}/nss3/nssckfw.h
%{_includedir}/nss3/nssckfwc.h
%{_includedir}/nss3/nssckfwt.h
%{_includedir}/nss3/nssckg.h
%{_includedir}/nss3/nssckmdt.h
%{_includedir}/nss3/nssckt.h
%{_includedir}/nss3/templates/nssck.api
%{_libdir}/libnssb.a
%{_libdir}/libnssckfw.a

%files util
%{!?_licensedir:%global license %%doc}
%license nss/COPYING
%{_libdir}/libnssutil3.so

%files util-devel
# package configuration files
%{_libdir}/pkgconfig/nss-util.pc
%{_bindir}/nss-util-config

# co-owned with nss
%dir %{_includedir}/nss3
# these are marked as public export in nss/lib/util/manifest.mk
%{_includedir}/nss3/base64.h
%{_includedir}/nss3/ciferfam.h
%{_includedir}/nss3/eccutil.h
%{_includedir}/nss3/hasht.h
%{_includedir}/nss3/nssb64.h
%{_includedir}/nss3/nssb64t.h
%{_includedir}/nss3/nsslocks.h
%{_includedir}/nss3/nssilock.h
%{_includedir}/nss3/nssilckt.h
%{_includedir}/nss3/nssrwlk.h
%{_includedir}/nss3/nssrwlkt.h
%{_includedir}/nss3/nssutil.h
%{_includedir}/nss3/pkcs1sig.h
%{_includedir}/nss3/pkcs11.h
%{_includedir}/nss3/pkcs11f.h
%{_includedir}/nss3/pkcs11n.h
%{_includedir}/nss3/pkcs11p.h
%{_includedir}/nss3/pkcs11t.h
%{_includedir}/nss3/pkcs11u.h
%{_includedir}/nss3/pkcs11uri.h
%{_includedir}/nss3/portreg.h
%{_includedir}/nss3/secasn1.h
%{_includedir}/nss3/secasn1t.h
%{_includedir}/nss3/seccomon.h
%{_includedir}/nss3/secder.h
%{_includedir}/nss3/secdert.h
%{_includedir}/nss3/secdig.h
%{_includedir}/nss3/secdigt.h
%{_includedir}/nss3/secerr.h
%{_includedir}/nss3/secitem.h
%{_includedir}/nss3/secoid.h
%{_includedir}/nss3/secoidt.h
%{_includedir}/nss3/secport.h
%{_includedir}/nss3/utilmodt.h
%{_includedir}/nss3/utilpars.h
%{_includedir}/nss3/utilparst.h
%{_includedir}/nss3/utilrename.h
%{_includedir}/nss3/templates/templates.c

%files softokn
%{_libdir}/libnssdbm3.so
%{_libdir}/libnssdbm3.chk
%{_libdir}/libsoftokn3.so
%{_libdir}/libsoftokn3.chk
# shared with nss-tools
%dir %{_libdir}/nss
%dir %{saved_files_dir}
%dir %{unsupported_tools_directory}
%{unsupported_tools_directory}/bltest
%{unsupported_tools_directory}/dbtool
%{unsupported_tools_directory}/ecperf
%{unsupported_tools_directory}/fbectest
%{unsupported_tools_directory}/fipstest
%{unsupported_tools_directory}/shlibsign

%files softokn-freebl
%{!?_licensedir:%global license %%doc}
%license nss/COPYING
%{_libdir}/libfreebl3.so
%{_libdir}/libfreebl3.chk
%{_libdir}/libfreeblpriv3.so
%{_libdir}/libfreeblpriv3.chk
#shared
%dir %{dracut_modules_dir}
%{dracut_modules_dir}/module-setup.sh
%{dracut_conf_dir}/50-nss-softokn.conf

%files softokn-freebl-devel
%{_libdir}/libfreebl.a
%{_includedir}/nss3/blapi.h
%{_includedir}/nss3/blapit.h
%{_includedir}/nss3/alghmac.h
%{_includedir}/nss3/cmac.h
%{_includedir}/nss3/lowkeyi.h
%{_includedir}/nss3/lowkeyti.h

%files softokn-devel
%{_libdir}/pkgconfig/nss-softokn.pc
%{_bindir}/nss-softokn-config

# co-owned with nss
%dir %{_includedir}/nss3
#
# The following headers are those exported public in
# nss/lib/freebl/manifest.mn and
# nss/lib/softoken/manifest.mn
#
# The following list is short because many headers, such as
# the pkcs #11 ones, have been provided by nss-util-devel
# which installed them before us.
#
%{_includedir}/nss3/ecl-exp.h
%{_includedir}/nss3/nsslowhash.h
%{_includedir}/nss3/shsign.h


%changelog
* Tue Jan 23 2024 Bob Relyea <rrelyea@redhat.com> - 3.90.0-6
- Fix ecc DER wrapping.

* Wed Jan 17 2024 Bob Relyea <rrelyea@redhat.com> - 3.90.0-5
- Pick up validated constant time implementations of p256, p384, and p521
  from upsream
- More Fips indicator changes

* Wed Dec 6 2023 Bob Relyea <rrelyea@redhat.com> - 3.90.0-4
- FIPS review changes
-   add PORT_SafeZero to avoid compiler optimizing a way zeroing memory.
-   update the indicators for this release
-   allow hashing of longer than int32 values in a single PKCS #11 call.

* Tue Nov 21 2023 Bob Relyea <rrelyea@redhat.com> - 3.90.0-3.1
- Fix expired certs in tests
- Fix CVE-2023-5388

* Thu Aug 3 2023 Bob Relyea <rrelyea@redhat.com> - 3.90.0-3
- add indicators for pbkdf2
- add camellia to pkcs12 doc files
- fix ems policy bug
- disable ech

* Thu Jul 27 2023 Bob Relyea <rrelyea@redhat.com> - 3.90.0-2
- fix the change log

* Thu Jul 27 2023 Bob Relyea <rrelyea@redhat.com> - 3.90.0-1
- rebase to NSS 3.90

* Wed Mar 8 2023 Bob Relyea <rrelyea@redhat.com> - 3.79.0-11
- Fix CVE-2023-0767

* Thu Aug 11 2022 Bob Relyea <rrelyea@redhat.com> - 3.79.0-10
- Fix QA found failures:
-  remove extra '+' from sslpolicy.txt file causing test error values
-  only use GRND_RANDOM if the kernel is in FIPS mode.

* Fri Aug 5 2022 Bob Relyea <rrelyea@redhat.com> - 3.79.0-9
- FIPS 140-3 changes

* Wed Jul 13 2022 Bob Relyea <rrelyea@redhat.com> - 3.79.0-8
- Update fips default for pk12util to AES rather than TDES
- Fix bug in pkcs12 files with null passwords

* Wed Jul 6 2022 Bob Relyea <rrelyea@redhat.com> - 3.79.0-7
- Better fix for test regressions

* Mon Jun 27 2022 Bob Relyea <rrelyea@redhat.com> - 3.79.0-6
- fix nss.spec so it works in a rhel-8.1.0 buildroot

* Mon Jun 20 2022 Bob Relyea <rrelyea@redhat.com> - 3.79.0-5
- FIPS 140-3 changes
-  Reject Small RSA keys, 1024 bit keys are marked as FIP OK when verifying, reject
   signature keys by policy
-  Allow applications to retrigger selftests on demand.

* Fri Jun 17 2022 Bob Relyea <rrelyea@redhat.com> - 3.79.0-4
- Fix pkgconfig output

* Wed Jun 15 2022 Bob Relyea <rrelyea@redhat.com> - 3.79.0-3
- NSR Coverity fix changed selfserv from passive to active, change it back

* Sat Jun 11 2022 Bob Relyea <rrelyea@redhat.com> - 3.79.0-2
- Fix regressions found in test suites.

* Thu Jun 2 2022 Bob Relyea <rrelyea@redhat.com> - 3.79.0-1
- Rebase to NSS 3.79
- Set FIPS Module ID
- skip attribute verification on attributes with default values
- don't export trust objects if they are default trust objects from dbm
- add dbtool to nss-tools

* Thu Nov 18 2021 Bob Relyea <rrelyea@redhat.com> - 3.67.0-7
- Fix CVE 2021 43527

* Tue Jul 6 2021 Bob Relyea <rrelyea@redhat.com> - 3.67.0-6
- Fix ssl alert issue

* Thu Jul 1 2021 Bob Relyea <rrelyea@redhat.com> - 3.67.0-5
- Fix issue with reading databases that were updated using
  unpatched versions of nss

* Tue Jun 29 2021 Bob Relyea <rrelyea@redhat.com> - 3.67.0-4
- Better fix for the sdb timeout. The issue wasn't a race, it was
  the sqlite timeout waiting to begin a transaction under heavy
  thread usage.

* Mon Jun 28 2021 Bob Relyea <rrelyea@redhat.com> - 3.67.0-3
- Fix sdb race condition

* Fri Jun 18 2021 Bob Relyea <rrelyea@redhat.com> - 3.67.0-2
- Fix coverity issues

* Thu Jun 17 2021 Bob Relyea <rrelyea@redhat.com> - 3.67.0-1
- Rebase to NSS 3.67

* Tue Jun 15 2021 Bob Relyea <rrelyea@redhat.com> - 3.66.0-2
- Restore old pkcs12 defaults.

* Mon Jun 14 2021 Bob Relyea <rrelyea@redhat.com> - 3.66.0-1.1
- build nss for older nspr so we can pass gating with
  the new nspr in the build root

* Wed Jun 2 2021 Bob Relyea <rrelyea@redhat.com> - 3.66.0-1
- Rebase to NSS 3.66

* Thu Dec 3 2020 Bob Relyea <rrelyea@redhat.com> - 3.53.1-17
- Fix various corner cases with ike v1 app b support.

* Thu Nov 19 2020 Bob Relyea <rrelyea@redhat.com> - 3.53.1-16
- Fix the following CVE
- CVE-2020-12403 chacha-poly issues
- CVE-2020-12400 constant time ECC.
- CVE-2020-6829  constant time ECC.

* Wed Nov 4 2020 Bob Relyea <rrelyea@redhat.com> - 3.53.1-15
- Revert some policy changes the generate ABI runtime issues.

* Thu Oct 29 2020 Bob Relyea <rrelyea@redhat.com> - 3.53.1-14
- Add support for enable/disable in policy. Now if your policy
  file has disallow=x enable=y it will act just like our other 
  libraries.

* Mon Oct 26 2020 Bob Relyea <rrelyea@redhat.com> - 3.53.1-13
- Add OAEP interface so applications can wrap keys with RSA-OAEP
  rather than RSA-PKCS-1.

* Mon Oct 19 2020 Bob Relyea <rrelyea@redhat.com> - 3.53.1-12
- fips need to reject small primes even if they are approved
- code to autodetect whether or not to use the cache needs to do so
  in a way that doesn't mess with filesystem negative file caching.
- add kdf selftests

* Thu Jul 30 2020 Bob Relyea <rrelyea@redhat.com> - 3.53.1-11
- Fix issue with upgradedb where upgradedb expects standard to
  generate dbm databases, not sql databases (default in RHEL8)

* Thu Jul 30 2020 Bob Relyea <rrelyea@redhat.com> - 3.53.1-10
- Disable dh timing test because it's unreliable on s390

* Thu Jul 30 2020 Daiki Ueno <dueno@redhat.com> - 3.53.1-9
- Explicitly enable upgradedb/sharedb test cycles

* Wed Jul 29 2020 Daiki Ueno <dueno@redhat.com> - 3.53.1-8
- Disable Delegated Credentials for TLS

* Fri Jul 24 2020 Bob Relyea <rrelyea@redhat.com> - 3.53.1-7
- Fix attribute decryption issue where the private key components
  integrity check on private attributes where not being checked.

* Mon Jul 13 2020 Daiki Ueno <dueno@redhat.com> - 3.53.1-6
- Update nss-rsa-pkcs1-sigalgs.patch to the upstream version

* Sat Jul 11 2020 Bob Relyea <rrelyea@redhat.com> - 3.53.1-5
- Include required checks for dh and ecdh key generation in FIPS mode.

* Wed Jul 8 2020 Bob Relyea <rrelyea@redhat.com> - 3.53.1-4
- Add better checks for dh derive operations in FIPS mode.

* Thu Jun 25 2020 Daiki Ueno <dueno@redhat.com> - 3.53.1-3
- Disable NSS_HASH_ALG_SUPPORT as well for MD5 (#1849938)
- Adjust for update-crypto-policies packaging change (#1848649)
- Fix compilation with -Werror=strict-prototypes (#1843417)

* Wed Jun 24 2020 Daiki Ueno <dueno@redhat.com> - 3.53.1-2
- Fix regression in MD5 disablement (#1849938)
- Include rsa_pkcs1_* in signature_algorithms extension (#1847945)

* Mon Jun 22 2020 Daiki Ueno <dueno@redhat.com> - 3.53.1-1
- Update to NSS 3.53.1

* Sat Jun  6 2020 Daiki Ueno <dueno@redhat.com> - 3.53.0-1
- Update to NSS 3.53

* Fri Jan 31 2020 Bob Relyea <rrelyea@redhat.com> - 3.44.0-15
- Fix swapped CMAC PKCS #11 values.
- Fix data alignment crash in CMAC.

* Tue Dec 3 2019 Bob Relyea <rrelyea@redhat.com> - 3.44.0-14
- Fix coverify scan issue

* Mon Dec 2 2019 Bob Relyea <rrelyea@redhat.com> - 3.44.0-13
- Fix endian problem in SP-800 108 code.

* Thu Nov 28 2019 Daiki Ueno <dueno@redhat.com> - 3.44.0-12
- Install cmac.h required by blapi.h (#1764513)
- Fix out-of-bounds write in NSC_EncryptUpdate (#1775913)

* Wed Nov 27 2019 Bob Relyea <rrelyea@redhat.com> - 3.44.0-11
- Add SP-800 108 Generalized kdf

* Mon Nov 11 2019 Daiki Ueno <dueno@redhat.com> - 3.44.0-10
- Check policy against hash algorithms used for ServerKeyExchange (#1730039)

* Wed Nov  6 2019 Bob Relyea <rrelyea@redhat.com> - 3.44.0-9
- Add CMAC

* Thu Aug  8 2019 Bob Relyea <rrelyea@redhat.com> - 3.44.0-8
- CKM_NSS_IKE1_APP_B_PRF_DERIVE was missing from the mechanism list, preventing
  PK11_Derive*() from using it. Add gtests for the PK11_Derive interface for
  all the CKM_NSS_IKE*_DERIVE mechanism.

* Wed Jul  3 2019 Daiki Ueno <dueno@redhat.com> - 3.44.0-7
- Backport fixes from 3.44.1

* Wed Jun 26 2019 Daiki Ueno <dueno@redhat.com> - 3.44.0-6
- Add continuous RNG test required by FIPS
- fipstest: use CKM_TLS12_MASTER_KEY_DERIVE instead of vendor specific mechanism

* Mon Jun 10 2019 Daiki Ueno <dueno@redhat.com> - 3.44.0-5
- Rebuild with the correct build target

*Fri Jun 7 2019 Bob Relyea <rrelyea@redhat.com> - 3.44.0-4.1
- rebuild to try to retrigger CI tests

*Wed Jun 5 2019 Bob Relyea <rrelyea@redhat.com> - 3.44.0-4
- Fix certutil man page
- Fix extracting a public key from a private key for dh, ec, and dsa

* Thu May 30 2019 Daiki Ueno <dueno@redhat.com> - 3.44.0-3
- Disable TLS 1.3 under FIPS mode
- Disable RSASSA-PKCS1-v1_5 in TLS 1.3
- Fix post-handshake auth transcript calculation if
  SSL_ENABLE_SESSION_TICKETS is set
- Revert the change to use XDG basedirs (mozilla#818686)

* Fri May 24 2019 Bob Relyea <rrelyea@redhat.com> - 3.44.0-2
- Add ike mechanisms in softokn
- Add FIPS checks in softoken

* Fri May 24 2019 Daiki Ueno <dueno@redhat.com> - 3.44.0-1
- Update to NSS 3.44
- Define NSS_SEED_ONLY_DEV_URANDOM=1 to exclusively use getentropy
- Use %%autosetup
- Clean up manual pages generation
- Clean up %%check
- Remove prelink dependency, which is not available in RHEL-8
- Remove upstreamed patches

* Mon Dec 17 2018 Daiki Ueno <dueno@redhat.com> - 3.41.0-5
- Update manual pages to reflect recent changes in commands

* Fri Dec 14 2018 Bob Relyea <rrelyea@redhat.com> - 3.41.0-4
- Make sure corresponding public keys are created when importing private keys.

* Thu Dec 13 2018 Daiki Ueno <dueno@redhat.com> - 3.41.0-3
- Fix the last change
- Add --no-reload option to update-crypto-policies to avoid
  unnecessary restart of daemons

* Thu Dec 13 2018 Daiki Ueno <dueno@redhat.com> - 3.41.0-2
- Restore LDFLAGS injection when linking DSO

* Mon Dec 10 2018 Daiki Ueno <dueno@redhat.com> - 3.41.0-1
- Update to NSS 3.41
- Consolidate nss-util, nss-softokn, and nss into a single source package

* Fri Dec  7 2018 Daiki Ueno <dueno@redhat.com> - 3.39.0-1.5
- Fix the last commit

* Tue Dec 4 2018 Bob Relyea <rrelyea@redhat.com> - 3.39.0-1.4
- Support for IKE/IPsec typical PKIX usage so libreswan can use nss
  without rejecting certs based on EKU

* Thu Nov 29 2018 Daiki Ueno <dueno@redhat.com> - 3.39.0-1.3
- Backport upstream fixes for rhbz#1649026, rhbz#1608895, rhbz#1644854
- Document PKCS #11 URI
- Add warning when adding module with modutil while p11-kit is enabled

* Tue Nov 13 2018 Daiki Ueno <dueno@redhat.com> - 3.39.0-1.2
- Update nss-dsa.patch to not advertise DSA signature algorithm
- Update PayPal test certs for testing

* Thu Oct 18 2018 Daiki Ueno <dueno@redhat.com> - 3.39.0-1.1
- Backport "DSA" keyword in crypto-policies

* Tue Sep 25 2018 Daiki Ueno <dueno@redhat.com> - 3.39.0-1.0
- Update to NSS 3.39

* Fri Sep 14 2018 Daiki Ueno <dueno@redhat.com> - 3.38.0-1.2
- Fix LDFLAGS injection when linking DSO

* Tue Jul 24 2018 Daiki Ueno <dueno@redhat.com> - 3.38.0-1.1
- Install crypto-policies configuration file for
  https://fedoraproject.org/wiki/Changes/NSSLoadP11KitModules
- Port enable-fips-when-system-is-in-fips-mode.patch from RHEL-7
- Use %%ldconfig_scriptlets
- Remove needless use of %defattr, by Jason Tibbitts

* Wed Jul 18 2018 Daiki Ueno <dueno@redhat.com> - 3.38.0-1.0
- Update to NSS 3.38

* Tue Jul 17 2018 Kai Engert <kaie@redhat.com> - 3.36.1-1.2
- Backport upstream addition of nss-policy-check utility, rhbz#1428746,
  includes required fixes for mozbz#1296263 and mozbz#1474875

* Fri May 25 2018 Daiki Ueno <dueno@redhat.com> - 3.36.1-1.1
- Switch the default DB type to SQL
- Enable SSLKEYLOGFILE

* Wed Apr 11 2018 Daiki Ueno <dueno@redhat.com> - 3.36.1-1.0
- Update to NSS 3.36.1
- Remove nss-3.14.0.0-disble-ocsp-test.patch
- Fix partial injection of LDFLAGS
- Remove NSS_NO_PKCS11_BYPASS, which is no-op in upstream

* Fri Mar  9 2018 Daiki Ueno <dueno@redhat.com> - 3.36.0-1.0
- Update to NSS 3.36.0
- Add gcc-c++ to BuildRequires (C++ is needed for gtests)
- Make test failure detection robuster

* Thu Feb 08 2018 Fedora Release Engineering <releng@fedoraproject.org> - 3.35.0-5
- Rebuilt for https://fedoraproject.org/wiki/Fedora_28_Mass_Rebuild

* Mon Jan 29 2018 Kai Engert <kaie@redhat.com> - 3.35.0-4
- Fix a compiler error with gcc 8, mozbz#1434070
- Set NSS_FORCE_FIPS=1 at %%build time, and remove from %%check.

* Mon Jan 29 2018 Kai Engert <kaie@redhat.com> - 3.35.0-3
- Stop pulling in nss-pem automatically, packages that need it should
  depend on it, rhbz#1539401

* Tue Jan 23 2018 Daiki Ueno <dueno@redhat.com> - 3.35.0-2
- Update to NSS 3.35.0

* Tue Nov 14 2017 Daiki Ueno <dueno@redhat.com> - 3.34.0-2
- Update to NSS 3.34.0

* Fri Nov 10 2017 Daiki Ueno <dueno@redhat.com> - 3.33.0-6
- Make sure 32bit nss-pem always be installed with 32bit nss in
  multlib environment, patch by Kamil Dudka

* Wed Nov  8 2017 Kai Engert <kaie@redhat.com> - 3.33.0-5
- Fix test script

* Tue Nov  7 2017 Kai Engert <kaie@redhat.com> - 3.33.0-4
- Update tests to be compatible with default NSS DB changed to sql
  (the default was changed in the nss-util package).

* Tue Oct 24 2017 Kai Engert <kaie@redhat.com> - 3.33.0-3
- rhbz#1505487, backport upstream fixes required for rhbz#1496560

* Tue Oct  3 2017 Daiki Ueno <dueno@redhat.com> - 3.33.0-2
- Update to NSS 3.33.0

* Fri Sep 15 2017 Daiki Ueno <dueno@redhat.com> - 3.32.1-2
- Update to NSS 3.32.1

* Wed Sep  6 2017 Daiki Ueno <dueno@redhat.com> - 3.32.0-4
- Update iquote.patch to really prefer in-tree headers over system headers

* Wed Aug 23 2017 Kai Engert <kaie@redhat.com> - 3.32.0-3
- NSS libnssckbi.so has already been obsoleted by p11-kit-trust, rhbz#1484449

* Mon Aug  7 2017 Daiki Ueno <dueno@redhat.com> - 3.32.0-2
- Update to NSS 3.32.0

* Thu Aug 03 2017 Fedora Release Engineering <releng@fedoraproject.org> - 3.31.0-6
- Rebuilt for https://fedoraproject.org/wiki/Fedora_27_Binutils_Mass_Rebuild

* Thu Jul 27 2017 Fedora Release Engineering <releng@fedoraproject.org> - 3.31.0-5
- Rebuilt for https://fedoraproject.org/wiki/Fedora_27_Mass_Rebuild

* Tue Jul 18 2017 Daiki Ueno <dueno@redhat.com> - 3.31.0-4
- Backport mozbz#1381784 to avoid deadlock in dnf

* Thu Jul 13 2017 Daiki Ueno <dueno@redhat.com> - 3.31.0-3
- Move signtool to %%_libdir/nss/unsupported-tools, for:
  https://fedoraproject.org/wiki/Changes/NSSSigntoolDeprecation

* Wed Jun 21 2017 Daiki Ueno <dueno@redhat.com> - 3.31.0-2
- Rebase to NSS 3.31.0

* Fri Jun  2 2017 Daiki Ueno <dueno@redhat.com> - 3.30.2-3
- Enable gtests

* Mon Apr 24 2017 Daiki Ueno <dueno@redhat.com> - 3.30.2-2
- Rebase to NSS 3.30.2
- Enable TLS 1.3

* Thu Mar 30 2017 Kai Engert <kaie@redhat.com> - 3.30.0-3
- Backport upstream mozbz#1328318 to support crypto policy FUTURE.

* Tue Mar 21 2017 Daiki Ueno <dueno@redhat.com> - 3.30.0-2
- Rebase to NSS 3.30.0
- Remove upstreamed patches

* Thu Mar 02 2017 Kai Engert <kaie@redhat.com> - 3.29.1-3
- Backport mozbz#1334976 and mozbz#1336487.

* Fri Feb 17 2017 Daiki Ueno <dueno@redhat.com> - 3.29.1-2
- Rebase to NSS 3.29.1

* Thu Feb  9 2017 Daiki Ueno <dueno@redhat.com> - 3.29.0-3
- Disable TLS 1.3, following the upstream change

* Wed Feb  8 2017 Daiki Ueno <dueno@redhat.com> - 3.29.0-2
- Rebase to NSS 3.29.0
- Suppress -Werror=int-in-bool-context warnings with GCC7

* Mon Jan 23 2017 Daiki Ueno <dueno@redhat.com> - 3.28.1-6
- Work around pkgconfig -> pkgconf transition issue (releng#6597)

* Fri Jan 20 2017 Daiki Ueno <dueno@redhat.com> - 3.28.1-5
- Disable TLS 1.3
- Add "Conflicts" with packages using older Mozilla codebase, which is
  not compatible with NSS 3.28.1
- Remove NSS_ECC_MORE_THAN_SUITE_B setting, as it was removed in upstream

* Tue Jan 17 2017 Daiki Ueno <dueno@redhat.com> - 3.28.1-4
- Add "Conflicts" with older firefox packages which don't have support
  for smaller curves added in NSS 3.28.1

* Fri Jan 13 2017 Daiki Ueno <dueno@redhat.com> - 3.28.1-3
- Fix incorrect version specification in %%nss_{util,softokn}_version,
  pointed by Elio Maldonado

* Fri Jan  6 2017 Daiki Ueno <dueno@redhat.com> - 3.28.1-2
- Rebase to NSS 3.28.1
- Remove upstreamed patch for disabling RSA-PSS
- Re-enable TLS 1.3

* Wed Nov 30 2016 Daiki Ueno <dueno@redhat.com> - 3.27.2-2
- Rebase to NSS 3.27.2

* Tue Nov 15 2016 Daiki Ueno <dueno@redhat.com> - 3.27.0-5
- Revert the previous fix for RSA-PSS and use the upstream fix instead

* Wed Nov 02 2016 Kai Engert <kaie@redhat.com> - 3.27.0-4
- Disable the use of RSA-PSS with SSL/TLS. #1383809

* Sun Oct  2 2016 Daiki Ueno <dueno@redhat.com> - 3.27.0-3
- Disable TLS 1.3 for now, to avoid reported regression with TLS to
  version intolerant servers

* Thu Sep 29 2016 Daiki Ueno <dueno@redhat.com> - 3.27.0-2
- Rebase to NSS 3.27.0
- Remove upstreamed ectest patch

* Mon Aug  8 2016 Daiki Ueno <dueno@redhat.com> - 3.26.0-2
- Rebase to NSS 3.26.0
- Update check policy file patch to better match what was upstreamed
- Remove conditionally ignore system policy patch as it has been upstreamed
- Skip ectest as well as ecperf, which are built as part of nss-softokn
- Fix rpmlint error regarding %%define usage

* Thu Jul 14 2016 Elio Maldonado <emaldona@redhat.com> - 3.25.0-6
- Incorporate some changes requested in upstream review and commited upstream (#1157720)

* Fri Jul 01 2016 Elio Maldonado <emaldona@redhat.com> - 3.25.0-5
- Add support for conditionally ignoring the system policy (#1157720)
- Remove unneeded test scripts patches in order to run more tests
- Remove unneeded test data modifications from the spec file

* Tue Jun 28 2016 Elio Maldonado <emaldona@redhat.com> - 3.25.0-4
- Remove obsolete patch and spurious lines from the spec file (#1347336)

* Sun Jun 26 2016 Elio Maldonado <emaldona@redhat.com> - 3.25.0-3
- Cleanup spec file and patches and add references to bugs filed upstream

* Fri Jun 24 2016 Elio Maldonado <emaldona@redhat.com> - 3.25.0-2
- Rebase to nss 3.25

* Thu Jun 16 2016 Kamil Dudka <kdudka@redhat.com> - 3.24.0-3
- decouple nss-pem from the nss package (#1347336)

* Fri Jun 03 2016 Elio Maldonado <emaldona@redhat.com> - 3.24.0-2.3
- Apply the patch that was last introduced
- Renumber and reorder some of the patches
- Resolves: Bug 1342158

* Thu Jun 02 2016 Elio Maldonado <emaldona@redhat.com> - 3.24.0-2.2
- Allow application requests to disable SSL v2 to succeed
- Resolves: Bug 1342158 - nss-3.24 does no longer support ssl V2, installation of IPA fails because nss init fails

* Sun May 29 2016 Elio Maldonado <emaldona@redhat.com> - 3.24.0-2.1
- Rebase to NSS 3.24.0
- Restore setting the policy file location
- Make ssl tests scripts aware of policy
- Ajust tests data expected result for policy

* Tue May 24 2016 Elio Maldonado <emaldona@redhat.com> - 3.24.0-2.0
- Bootstrap build to rebase to NSS 3.24.0
- Temporarily not setting the policy file location

* Thu May 12 2016 Elio Maldonado <emaldona@redhat.com> - 3.23.0-9
- Change POLICY_FILE to "nss.config"

* Fri Apr 22 2016 Elio Maldonado <emaldona@redhat.com> - 3.23.0-8
- Change POLICY_FILE to "nss.cfg"

* Wed Apr 20 2016 Elio Maldonado <emaldona@redhat.com> - 3.23.0-7
- Change the POLICY_PATH to "/etc/crypto-policies/back-ends"
- Regenerate the check policy patch with hg to provide more context

* Thu Apr 14 2016 Elio Maldonado <emaldona@redhat.com> - 3.23.0-6
- Fix typo in the last %%changelog entry

* Thu Mar 24 2016 Elio Maldonado <emaldona@redhat.com> - 3.23.0-5
- Load policy file if /etc/pki/nssdb/policy.cfg exists
- Resolves: Bug 1157720 - NSS should enforce the system-wide crypto policy

* Tue Mar 08 2016 Elio Maldonado <emaldona@redhat.com> - 3.23.0-4
- Remove unused patch rendered obsolete by pem update

* Tue Mar 08 2016 Elio Maldonado <emaldona@redhat.com> - 3.23.0-3
- Update pem sources to latest from nss-pem upstream
- Resolves: Bug 1300652 - [PEM] insufficient input validity checking while loading a private key

* Sat Mar 05 2016 Elio Maldonado <emaldona@redhat.com> - 3.23.0-2
- Rebase to NSS 3.23

* Sat Feb 27 2016 Elio Maldonado <emaldona@redhat.com> - 3.22.2-2
- Rebase to NSS 3.22.2

* Tue Feb 23 2016 Elio Maldonado <emaldona@redhat.com> - 3.22.1-3
- Fix ssl2/exp test disabling to run all the required tests

* Sun Feb 21 2016 Elio Maldonado <emaldona@redhat.com> - 3.22.1-1
- Rebase to NSS 3.22.1

* Mon Feb 08 2016 Elio Maldonado <emaldona@redhat.com> - 3.22.0-3
- Update .gitignore as part of updating to nss 3.22

* Mon Feb 08 2016 Elio Maldonado <emaldona@redhat.com> - 3.22.0-2
- Update to NSS 3.22

* Thu Feb 04 2016 Fedora Release Engineering <releng@fedoraproject.org> - 3.21.0-7
- Rebuilt for https://fedoraproject.org/wiki/Fedora_24_Mass_Rebuild

* Fri Jan 15 2016 Elio Maldonado <emaldona@redhat.com> - 3.21.0-6
- Resolves: Bug 1299040 - Enable ssl_gtests upstream test suite
- Remove 'export NSS_DISABLE_GTESTS=1' go ssl_gtests are built
- Use %%define when specifying the nss_tests to run

* Wed Dec 30 2015 Michal Toman <mtoman@fedoraproject.org> - 3.21.0-5
- Add 64-bit MIPS to multilib arches

* Fri Nov 20 2015 Elio Maldonado <emaldona@redhat.com> - 3.21.0-4
- Update %%{nss_util_version} and %%{nss_softokn_version} to 3.21.0
- Resolves: Bug 1284095 - all https fails with sec_error_no_token

* Sun Nov 15 2015 Elio Maldonado <emaldona@redhat.com> - 3.21.0-3
- Add references to bugs filed upstream

* Fri Nov 13 2015 Elio Maldonado Batiz <emaldona@redhat.com> - 3.21.1-2
- Update to NSS 3.21
- Package listsuites as part of the unsupported tools set
- Resolves: Bug 1279912 - nss-3.21 is available
- Resolves: Bug 1258425 - Use __isa_bits macro instead of list of 64-bit
- Resolves: Bug 1280032 - Package listsuites as part of the nss unsupported tools set

* Fri Oct 30 2015 Elio Maldonado <emaldona@redhat.com> - 3.20.1-2
- Update to NSS 3.20.1

* Wed Sep 30 2015 Elio Maldonado <emaldona@redhat.com> - 3.20.0-6
- Enable ECC cipher-suites by default [hrbz#1185708]
- Split the enabling patch in two for easier maintenance
- Remove unused patches rendered obsolete by prior rebase

* Wed Sep 16 2015 Elio Maldonado <emaldona@redhat.com> - 3.20.0-5
- Enable ECC cipher-suites by default [hrbz#1185708]
- Implement corrections requested in code review

* Tue Sep 15 2015 Elio Maldonado <emaldona@redhat.com> - 3.20.0-4
- Enable ECC cipher-suites by default [hrbz#1185708]

* Mon Sep 14 2015 Elio Maldonado <emaldona@redhat.com> - 3.20.0-3
- Fix patches that disable ssl2 and export cipher suites support
- Fix libssl patch that disable ssl2 & export cipher suites to not disable RSA_WITH_NULL ciphers
- Fix syntax errors in patch to skip ssl2 and export cipher suite tests
- Turn ssl2 off by default in the tstclnt tool
- Disable ssl stress tests containing TLS RC4 128 with MD5

* Thu Aug 20 2015 Elio Maldonado <emaldona@redhat.com> - 3.20.0-2
- Update to NSS 3.20

* Sat Aug 08 2015 Elio Maldonado <emaldona@redhat.com> - 3.19.3-2
- Update to NSS 3.19.3

* Fri Jun 26 2015 Elio Maldonado <emaldona@redhat.com> - 3.19.2-3
- Create on the fly versions of sslcov.txt and sslstress.txt that disable tests for SSL2 and EXPORT ciphers

* Wed Jun 17 2015 Kai Engert <kaie@redhat.com> - 3.19.2-2
- Update to NSS 3.19.2

* Thu May 28 2015 Kai Engert <kaie@redhat.com> - 3.19.1-2
- Update to NSS 3.19.1

* Tue May 19 2015 Kai Engert <kaie@redhat.com> - 3.19.0-2
- Update to NSS 3.19

* Fri May 15 2015 Kai Engert <kaie@redhat.com> - 3.18.0-2
- Replace expired test certificates, upstream bug 1151037

* Thu Mar 19 2015 Elio Maldonado <emaldona@redhat.com> - 3.18.0-1
- Update to nss-3.18.0
- Resolves: Bug 1203689 - nss-3.18 is available

* Tue Mar 03 2015 Elio Maldonado <emaldona@redhat.com> - 3.17.4-5
- Disable export suites and SSL2 support at build time
- Fix syntax errors in various shell scripts
- Resolves: Bug 1189952 - Disable SSL2 and the export cipher suites

* Sat Feb 21 2015 Till Maas <opensource@till.name> - 3.17.4-4
- Rebuilt for Fedora 23 Change
  https://fedoraproject.org/wiki/Changes/Harden_all_packages_with_position-independent_code

* Tue Feb 10 2015 Elio Maldonado <emaldona@redhat.com> - 3.17.4-3
- Commented out the export NSS_NO_SSL2=1 line to not disable ssl2
- Backing out from disabling ssl2 until the patches are fixed

* Mon Feb 09 2015 Elio Maldonado <emaldona@redhat.com> - 3.17.4-2
- Disable SSL2 support at build time
- Fix syntax errors in various shell scripts
- Resolves: Bug 1189952 - Disable SSL2 and the export cipher suites

* Wed Jan 28 2015 Elio Maldonado <emaldona@redhat.com> - 3.17.4-1
- Update to nss-3.17.4

* Sat Jan 24 2015 Ville Skyttä <ville.skytta@iki.fi> - 3.17.3-4
- Own the %%{_datadir}/doc/nss-tools dir

* Tue Dec 16 2014 Elio Maldonado <emaldona@redhat.com> - 3.17.3-3
- Resolves: Bug 987189 - nss-tools RPM conflicts with perl-PAR-Packer
- Install pp man page in %%{_datadir}/doc/nss-tools/pp.1
- Use %%{_mandir} instead of /usr/share/man as more generic

* Mon Dec 15 2014 Elio Maldonado <emaldona@redhat.com> - 3.17.3-2
- Install pp man page in alternative location
- Resolves: Bug 987189 - nss-tools RPM conflicts with perl-PAR-Packer

* Fri Dec 05 2014 Elio Maldonado <emaldona@redhat.com> - 3.17.3-1
- Update to nss-3.17.3
- Resolves: Bug 1171012 - nss-3.17.3 is available

* Thu Oct 16 2014 Elio Maldonado <emaldona@redhat.com> - 3.17.2-2
- Resolves: Bug 994599 - Enable TLS 1.2 by default

* Sun Oct 12 2014 Elio Maldonado <emaldona@redhat.com> - 3.17.2-1
- Update to nss-3.17.2

* Wed Sep 24 2014 Kai Engert <kaie@redhat.com> - 3.17.1-1
- Update to nss-3.17.1
- Add a mechanism to skip test suite execution during development work

* Thu Aug 21 2014 Kevin Fenzi <kevin@scrye.com> - 3.17.0-2
- Rebuild for rpm bug 1131960

* Tue Aug 19 2014 Elio Maldonado <emaldona@redhat.com> - 3.17.0-1
- Update to nss-3.17.0

* Sun Aug 17 2014 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 3.16.2-4
- Rebuilt for https://fedoraproject.org/wiki/Fedora_21_22_Mass_Rebuild

* Wed Jul 30 2014 Elio Maldonado <emaldona@redhat.com> - 3.16.2-3
- Replace expired PayPal test cert with current one to prevent build failure

* Fri Jul 18 2014 Tom Callaway <spot@fedoraproject.org> - 3.16.2-2
- fix license handling

* Sun Jun 29 2014 Elio Maldonado <emaldona@redhat.com> - 3.16.2-1
- Update to nss-3.16.2

* Sun Jun 15 2014 Elio Maldonado <emaldona@redhat.com> - 3.16.1-4
- Remove unwanted source directories at end of %%prep so it truly does it
- Skip the cipher suite already run as part of the nss-softokn build

* Sat Jun 07 2014 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 3.16.1-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_21_Mass_Rebuild

* Mon May 12 2014 Jaromir Capik <jcapik@redhat.com> - 3.16.1-2
- Replacing ppc64 and ppc64le with the power64 macro
- Related: Bug 1052545 - Trivial change for ppc64le in nss spec

* Tue May 06 2014 Elio Maldonado <emaldona@redhat.com> - 3.16.1-1
- Update to nss-3.16.1
- Update the iquote patch on account of the rebase
- Improve error detection in the %%section
- Resolves: Bug 1094702 - nss-3.16.1 is available

* Tue Mar 18 2014 Elio Maldonado <emaldona@redhat.com> - 3.16.0-1
- Update to nss-3.16.0
- Cleanup the copying of the tools man pages
- Update the iquote.patch on account of the rebase

* Tue Mar 04 2014 Elio Maldonado <emaldona@redhat.com> - 3.15.5-2
- Restore requiring nss_softokn_version >= 3.15.5

* Wed Feb 19 2014 Elio Maldonado <emaldona@redhat.com> - 3.15.5-1
- Update to nss-3.15.5
- Temporarily requiring only nss_softokn_version >= 3.15.4
- Fix location of sharedb files and their manpages
- Move cert9.db, key4.db, and pkcs11.txt to the main package
- Move nss-sysinit manpages tar archives to the main package
- Resolves: Bug 1066877 - nss-3.15.5 is available
- Resolves: Bug 1067091 - Move sharedb files to the %%files section

* Thu Feb 06 2014 Elio Maldonado <emaldona@redhat.com> - 3.15.4-5
- Revert previous change that moved some sysinit manpages
- Restore nss-sysinit manpages tar archives to %%files sysinit
- Removing spurious wildcard entry was the only change needed

* Mon Jan 27 2014 Elio Maldonado <emaldona@redhat.com> - 3.15.4-4
- Add explanatory comments for iquote.patch as was done on f20

* Sat Jan 25 2014 Elio Maldonado <emaldona@redhat.com> - 3.15.4-3
- Update pem sources to latest from nss-pem upstream
- Pick up pem fixes verified on RHEL and applied upstream
- Fix a problem where same files in two rpms created rpm conflict
- Move some nss-sysinit manpages tar archives to the %%files the
- All man pages are listed by name so there shouldn't be wildcard inclusion
- Add support for ppc64le, Resolves: Bug 1052545

* Mon Jan 20 2014 Peter Robinson <pbrobinson@fedoraproject.org> 3.15.4-2
- ARM tests pass so remove ARM conditional

* Tue Jan 07 2014 Elio Maldonado <emaldona@redhat.com> - 3.15.4-1
- Update to nss-3.15.4 (hg tag NSS_3_15_4_RTM)
- Resolves: Bug 1049229 - nss-3.15.4 is available
- Update pem sources to latest from the interim upstream for pem
- Remove no longer needed patches
- Update pem/rsawrapr.c patch on account of upstream changes to freebl/softoken
- Update iquote.patch on account of upstream changes

* Wed Dec 11 2013 Elio Maldonado <emaldona@redhat.com> - 3.15.3.1-1
- Update to nss-3.15.3.1 (hg tag NSS_3_15_3_1_RTM)
- Resolves: Bug 1040282 - nss: Mis-issued ANSSI/DCSSI certificate (MFSA 2013-117)
- Resolves: Bug 1040192 - nss-3.15.3.1 is available

* Tue Dec 03 2013 Elio Maldonado <emaldona@redhat.com> - 3.15.3-2
- Bump the release tag

* Sun Nov 24 2013 Elio Maldonado <emaldona@redhat.com> - 3.15.3-1
- Update to NSS_3_15_3_RTM
- Resolves: Bug 1031897 - CVE-2013-5605 CVE-2013-5606 CVE-2013-1741 nss: various flaws
- Fix option descriptions for setup-nsssysinit manpage
- Fix man page of nss-sysinit wrong path and other flaws
- Document email option for certutil manpage
- Remove unused patches

* Sun Oct 27 2013 Elio Maldonado <emaldona@redhat.com> - 3.15.2-3
- Revert one change from last commit to preserve full nss pluggable ecc supprt [1019245]

* Wed Oct 23 2013 Elio Maldonado <emaldona@redhat.com> - 3.15.2-2
- Use the full sources from upstream
- Bug 1019245 - ECDHE in openssl available -> NSS needs too for Firefox/Thunderbird

* Thu Sep 26 2013 Elio Maldonado <emaldona@redhat.com> - 3.15.2-1
- Update to NSS_3_15_2_RTM
- Update iquote.patch on account of modified prototype on cert.h installed by nss-devel

* Wed Aug 28 2013 Elio Maldonado <emaldona@redhat.com> - 3.15.1-7
- Update pem sources to pick up a patch applied upstream which a faulty merge had missed
- The pem module should not require unique file basenames

* Tue Aug 27 2013 Elio Maldonado <emaldona@redhat.com> - 3.15.1-6
- Update pem sources to the latest from interim upstream

* Mon Aug 19 2013 Elio Maldonado <emaldona@redhat.com> - 3.15.1-5
- Resolves: rhbz#996639 - Minor bugs in nss man pages
- Fix some typos and improve description and see also sections

* Sun Aug 11 2013 Elio Maldonado <emaldona@redhat.com> - 3.15.1-4
- Cleanup spec file to address most rpmlint errors and warnings
- Using double percent symbols to fix macro-in-comment warnings
- Ignore unversioned-explicit-provides nss-system-init per spec comments
- Ignore invalid-url Source0 as it comes from the git lookaside cache
- Ignore invalid-url Source12 as it comes from the git lookaside cache

* Thu Jul 25 2013 Elio Maldonado <emaldona@redhat.com> - 3.15.1-3
- Add man page for pkcs11.txt configuration file and cert and key databases
- Resolves: rhbz#985114 - Provide man pages for the nss configuration files

* Fri Jul 19 2013 Elio Maldonado <emaldona@redhat.com> - 3.15.1-2
- Fix errors in the man pages
- Resolves: rhbz#984106 - Add missing option descriptions to man pages for {cert|cms|crl}util
- Resolves: rhbz#982856 - Fix path to script in man page for nss-sysinit

* Tue Jul 02 2013 Elio Maldonado <emaldona@redhat.com> - 3.15.1-1
- Update to NSS_3_15_1_RTM
- Enable the iquote.patch to access newly introduced types

* Wed Jun 19 2013 Elio Maldonado <emaldona@redhat.com> - 3.15-5
- Install man pages for nss-tools and the nss-config and setup-nsssysinit scripts
- Resolves: rhbz#606020 - nss security tools lack man pages

* Tue Jun 18 2013 emaldona <emaldona@redhat.com> - 3.15-4
- Build nss without softoken or util sources in the tree
- Resolves: rhbz#689918

* Mon Jun 17 2013 emaldona <emaldona@redhat.com> - 3.15-3
- Update ssl-cbc-random-iv-by-default.patch

* Sun Jun 16 2013 Elio Maldonado <emaldona@redhat.com> - 3.15-2
- Fix generation of NSS_VMAJOR, NSS_VMINOR, and NSS_VPATCH for nss-config

* Sat Jun 15 2013 Elio Maldonado <emaldona@redhat.com> - 3.15-1
- Update to NSS_3_15_RTM

* Wed Apr 24 2013 Elio Maldonado <emaldona@redhat.com> - 3.15-0.1.beta1.2
- Fix incorrect path that hid failed test from view
- Add ocsp to the test suites to run but ...
- Temporarily disable the ocsp stapling tests
- Do not treat failed attempts at ssl pkcs11 bypass as fatal errors

* Thu Apr 04 2013 Elio Maldonado <emaldona@redhat.com> - 3.15-0.1.beta1.1
- Update to NSS_3_15_BETA1
- Update spec file, patches, and helper scripts on account of a shallower source tree

* Sun Mar 24 2013 Kai Engert <kaie@redhat.com> - 3.14.3-12
- Update expired test certificates (fixed in upstream bug 852781)

* Fri Mar 08 2013 Kai Engert <kaie@redhat.com> - 3.14.3-10
- Fix incorrect post/postun scripts. Fix broken links in posttrans.

* Wed Mar 06 2013 Kai Engert <kaie@redhat.com> - 3.14.3-9
- Configure libnssckbi.so to use the alternatives system
  in order to prepare for a drop in replacement.

* Fri Feb 15 2013 Elio Maldonado <emaldona@redhat.com> - 3.14.3-1
- Update to NSS_3_14_3_RTM
- sync up pem rsawrapr.c with softoken upstream changes for nss-3.14.3
- Resolves: rhbz#908257 - CVE-2013-1620 nss: TLS CBC padding timing attack
- Resolves: rhbz#896651 - PEM module trashes private keys if login fails
- Resolves: rhbz#909775 - specfile support for AArch64
- Resolves: rhbz#910584 - certutil -a does not produce ASCII output

* Mon Feb 04 2013 Elio Maldonado <emaldona@redhat.com> - 3.14.2-2
- Allow building nss against older system sqlite

* Fri Feb 01 2013 Elio Maldonado <emaldona@redhat.com> - 3.14.2-1
- Update to NSS_3_14_2_RTM

* Wed Jan 02 2013 Kai Engert <kaie@redhat.com> - 3.14.1-3
- Update to NSS_3_14_1_WITH_CKBI_1_93_RTM

* Sat Dec 22 2012 Elio Maldonado <emaldona@redhat.com> - 3.14.1-2
- Require nspr >= 4.9.4
- Fix changelog invalid dates

* Mon Dec 17 2012 Elio Maldonado <emaldona@redhat.com> - 3.14.1-1
- Update to NSS_3_14_1_RTM

* Wed Dec 12 2012 Elio Maldonado <emaldona@redhat.com> - 3.14-12
- Bug 879978 - Install the nssck.api header template where mod_revocator can access it
- Install nssck.api in /usr/includes/nss3/templates

* Tue Nov 27 2012 Elio Maldonado <emaldona@redhat.com> - 3.14-11
- Bug 879978 - Install the nssck.api header template in a place where mod_revocator can access it
- Install nssck.api in /usr/includes/nss3

* Mon Nov 19 2012 Elio Maldonado <emaldona@redhat.com> - 3.14-10
- Bug 870864 - Add support in NSS for Secure Boot

* Sat Nov 10 2012 Elio Maldonado <emaldona@redhat.com> - 3.14-9
- Disable bypass code at build time and return failure on attempts to enable at runtime
- Bug 806588 - Disable SSL PKCS #11 bypass at build time

* Sun Nov 04 2012 Elio Maldonado <emaldona@redhat.com> - 3.14-8
- Fix pk11wrap locking which fixes 'fedpkg new-sources' and 'fedpkg update' hangs
- Bug 872124 - nss-3.14 breaks fedpkg new-sources
- Fix should be considered preliminary since the patch may change upon upstream approval

* Thu Nov 01 2012 Elio Maldonado <emaldona@redhat.com> - 3.14-7
- Add a dummy source file for testing /preventing fedpkg breakage
- Helps test the fedpkg new-sources and upload commands for breakage by nss updates
- Related to Bug 872124 - nss 3.14 breaks fedpkg new-sources

* Thu Nov 01 2012 Elio Maldonado <emaldona@redhat.com> - 3.14-6
- Fix a previous unwanted merge from f18
- Update the SS_SSL_CBC_RANDOM_IV patch to match new sources while
- Keeping the patch disabled while we are still in rawhide and
- State in comment that patch is needed for both stable and beta branches
- Update .gitignore to download only the new sources

* Wed Oct 31 2012 Elio Maldonado <emaldona@redhat.com> - 3.14-5
- Fix the spec file so sechash.h gets installed
- Resolves: rhbz#871882 - missing header: sechash.h in nss 3.14

* Sat Oct 27 2012 Elio Maldonado <emaldona@redhat.com> - 3.14-4
- Update the license to MPLv2.0

* Wed Oct 24 2012 Elio Maldonado <emaldona@redhat.com> - 3.14-3
- Use only -f when removing unwanted headers

* Tue Oct 23 2012 Elio Maldonado <emaldona@redhat.com> - 3.14-2
- Add secmodt.h to the headers installed by nss-devel
- nss-devel must install secmodt.h which moved from softoken to pk11wrap with nss-3.14

* Mon Oct 22 2012 Elio Maldonado <emaldona@redhat.com> - 3.14-1
- Update to NSS_3_14_RTM

* Sun Oct 21 2012 Elio Maldonado <emaldona@redhat.com> - 3.14-0.1.rc.1
- Update to NSS_3_14_RC1
- update nss-589636.patch to apply to httpdserv
- turn off ocsp tests for now
- remove no longer needed patches
- remove headers shipped by nss-util

* Fri Oct 05 2012 Kai Engert <kaie@redhat.com> - 3.13.6-1
- Update to NSS_3_13_6_RTM

* Mon Aug 27 2012 Elio Maldonado <emaldona@redhat.com> - 3.13.5-8
- Rebase pem sources to fedora-hosted upstream to pick up two fixes from rhel-6.3
- Resolves: rhbz#847460 - Fix invalid read and free on invalid cert load
- Resolves: rhbz#847462 - PEM module may attempt to free uninitialized pointer
- Remove unneeded fix gcc 4.7 c++ issue in secmodt.h that actually undoes the upstream fix

* Mon Aug 13 2012 Elio Maldonado <emaldona@redhat.com> - 3.13.5-7
- Fix pluggable ecc support

* Fri Jul 20 2012 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 3.13.5-6
- Rebuilt for https://fedoraproject.org/wiki/Fedora_18_Mass_Rebuild

* Sun Jul 01 2012 Elio Maldonado <emaldona@redhat.com> - 3.13.5-5
- Fix checkin comment to prevent unwanted expansions of percents

* Sun Jul 01 2012 Elio Maldonado <emaldona@redhat.com> - 3.13.5-4
- Resolves: Bug 830410 - Missing Requires %%{?_isa}
- Use Requires: %%{name}%%{?_isa} = %%{version}-%%{release} on tools
- Drop zlib requires which rpmlint reports as error E: explicit-lib-dependency zlib
- Enable sha224 portion of powerup selftest when running test suites
- Require nspr 4.9.1

* Wed Jun 20 2012 Elio Maldonado <emaldona@redhat.com> - 3.13.5-3
- Resolves: rhbz#833529 - revert unwanted change to nss.pc.in

* Tue Jun 19 2012 Elio Maldonado <emaldona@redhat.com> - 3.13.5-2
- Resolves: rhbz#833529 - Remove unwanted space from the Libs: line on nss.pc.in

* Mon Jun 18 2012 Elio Maldonado <emaldona@redhat.com> - 3.13.5-1
- Update to NSS_3_13_5_RTM

* Fri Apr 13 2012 Elio Maldonado <emaldona@redhat.com> - 3.13.4-3
- Resolves: Bug 812423 - nss_Init leaks memory, fix from RHEL 6.3

* Sun Apr 08 2012 Elio Maldonado <emaldona@redhat.com> - 3.13.4-2
- Resolves: Bug 805723 - Library needs partial RELRO support added
- Patch coreconf/Linux.mk as done on RHEL 6.2

* Fri Apr 06 2012 Elio Maldonado <emaldona@redhat.com> - 3.13.4-1
- Update to NSS_3_13_4_RTM
- Update the nss-pem source archive to the latest version
- Remove no longer needed patches
- Resolves: Bug 806043 - use pem files interchangeably in a single process
- Resolves: Bug 806051 - PEM various flaws detected by Coverity
- Resolves: Bug 806058 - PEM pem_CreateObject leaks memory given a non-existing file name

* Wed Mar 21 2012 Elio Maldonado <emaldona@redhat.com> - 3.13.3-4
- Resolves: Bug 805723 - Library needs partial RELRO support added

* Fri Mar 09 2012 Elio Maldonado <emaldona@redhat.com> - 3.13.3-3
- Cleanup of the spec file
- Add references to the upstream bugs
- Fix typo in Summary for sysinit

* Thu Mar 08 2012 Elio Maldonado <emaldona@redhat.com> - 3.13.3-2
- Pick up fixes from RHEL
- Resolves: rhbz#800674 - Unable to contact LDAP Server during winsync
- Resolves: rhbz#800682 - Qpid AMQP daemon fails to load after nss update
- Resolves: rhbz#800676 - NSS workaround for freebl bug that causes openswan to drop connections

* Thu Mar 01 2012 Elio Maldonado <emaldona@redhat.com> - 3.13.3-1
- Update to NSS_3_13_3_RTM

* Mon Jan 30 2012 Tom Callaway <spot@fedoraproject.org> - 3.13.1-13
- fix issue with gcc 4.7 in secmodt.h and C++11 user-defined literals

* Thu Jan 26 2012 Elio Maldonado <emaldona@redhat.com> - 3.13.1-12
- Resolves: Bug 784672 - nss should protect against being called before nss_Init

* Fri Jan 13 2012 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 3.13.1-11
- Rebuilt for https://fedoraproject.org/wiki/Fedora_17_Mass_Rebuild

* Fri Jan 06 2012 Elio Maldonado <emaldona@redhat.com> - 3.13.1-11
- Deactivate a patch currently meant for stable branches only

* Fri Jan 06 2012 Elio Maldonado <emaldona@redhat.com> - 3.13.1-10
- Resolves: Bug 770682 - nss update breaks pidgin-sipe connectivity
- NSS_SSL_CBC_RANDOM_IV set to 0 by default and changed to 1 on user request

* Tue Dec 13 2011 elio maldonado <emaldona@redhat.com> - 3.13.1-9
- Revert to using current nss_softokn_version
- Patch to deal with lack of sha224 is no longer needed

* Tue Dec 13 2011 Elio Maldonado <emaldona@redhat.com> - 3.13.1-8
- Resolves: Bug 754771 - [PEM] an unregistered callback causes a SIGSEGV

* Mon Dec 12 2011 Elio Maldonado <emaldona@redhat.com> - 3.13.1-7
- Resolves: Bug 750376 - nss 3.13 breaks sssd TLS
- Fix how pem is built so that nss-3.13.x works with nss-softokn-3.12.y
- Only patch blapitest for the lack of sha224 on system freebl
- Completed the patch to make pem link against system freebl

* Mon Dec 05 2011 Elio Maldonado <emaldona@redhat.com> - 3.13.1-6
- Removed unwanted /usr/include/nss3 in front of the normal cflags include path
- Removed unnecessary patch dealing with CERTDB_TERMINAL_RECORD, it's visible

* Sun Dec 04 2011 Elio Maldonado <emaldona@redhat.com> - 3.13.1-5
- Statically link the pem module against system freebl found in buildroot
- Disabling sha224-related powerup selftest until we update softokn
- Disable sha224 and pss tests which nss-softokn 3.12.x doesn't support

* Fri Dec 02 2011 Elio Maldonado Batiz <emaldona@redhat.com> - 3.13.1-4
- Rebuild with nss-softokn from 3.12 in the buildroot
- Allows the pem module to statically link against 3.12.x freebl
- Required for using nss-3.13.x with nss-softokn-3.12.y for a merge inrto rhel git repo
- Build will be temprarily placed on buildroot override but not pushed in bodhi

* Fri Nov 04 2011 Elio Maldonado <emaldona@redhat.com> - 3.13.1-2
- Fix broken dependencies by updating the nss-util and nss-softokn versions

* Thu Nov 03 2011 Elio Maldonado <emaldona@redhat.com> - 3.13.1-1
- Update to NSS_3_13_1_RTM
- Update builtin certs to those from NSSCKBI_1_88_RTM

* Sat Oct 15 2011 Elio Maldonado <emaldona@redhat.com> - 3.13-1
- Update to NSS_3_13_RTM

* Sat Oct 08 2011 Elio Maldonado <emaldona@redhat.com> - 3.13-0.1.rc0.1
- Update to NSS_3_13_RC0

* Wed Sep 14 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.11-3
- Fix attempt to free initilized pointer (#717338)
- Fix leak on pem_CreateObject when given non-existing file name (#734760)
- Fix pem_Initialize to return CKR_CANT_LOCK on multi-treaded calls (#736410)

* Tue Sep 06 2011 Kai Engert <kaie@redhat.com> - 3.12.11-2
- Update builtins certs to those from NSSCKBI_1_87_RTM

* Tue Aug 09 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.11-1
- Update to NSS_3_12_11_RTM

* Sat Jul 23 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.10-6
- Indicate the provenance of stripped source tarball (#688015)

* Mon Jun 27 2011 Michael Schwendt <mschwendt@fedoraproject.org> - 3.12.10-5
- Provide virtual -static package to meet guidelines (#609612).

* Fri Jun 10 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.10-4
- Enable pluggable ecc support (#712556)
- Disable the nssdb write-access-on-read-only-dir tests when user is root (#646045)

* Fri May 20 2011 Dennis Gilmore <dennis@ausil.us> - 3.12.10-3
- make the testsuite non fatal on arm arches

* Tue May 17 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.10-2
- Fix crmf hard-coded maximum size for wrapped private keys (#703656)

* Fri May 06 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.10-1
- Update to NSS_3_12_10_RTM

* Wed Apr 27 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.10-0.1.beta1
- Update to NSS_3_12_10_BETA1

* Mon Apr 11 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.9-15
- Implement PEM logging using NSPR's own (#695011)

* Wed Mar 23 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.9-14
- Update to NSS_3.12.9_WITH_CKBI_1_82_RTM

* Thu Feb 24 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.9-13
- Short-term fix for ssl test suites hangs on ipv6 type connections (#539183)

* Fri Feb 18 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.9-12
- Add a missing requires for pkcs11-devel (#675196)

* Tue Feb 15 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.9-11
- Run the test suites in the check section (#677809)

* Thu Feb 10 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.9-10
- Fix cms headers to not use c++ reserved words (#676036)
- Reenabling Bug 499444 patches
- Fix to swap internal key slot on fips mode switches

* Tue Feb 08 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.9-9
- Revert patches for 499444 until all c++ reserved words are found and extirpated

* Tue Feb 08 2011 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 3.12.9-8
- Rebuilt for https://fedoraproject.org/wiki/Fedora_15_Mass_Rebuild

* Tue Feb 08 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.9-7
- Fix cms header to not use c++ reserved word (#676036)
- Reenable patches for bug 499444

* Tue Feb 08 2011 Christopher Aillon <caillon@redhat.com> - 3.12.9-6
- Revert patches for 499444 as they use a C++ reserved word and
  cause compilation of Firefox to fail

* Fri Feb 04 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.9-5
- Fix the earlier infinite recursion patch (#499444)
- Remove a header that now nss-softokn-freebl-devel ships

* Tue Feb 01 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.9-4
- Fix infinite recursion when encoding NSS enveloped/digested data (#499444)

* Mon Jan 31 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.9-3
- Update the cacert trust patch per upstream review requests (#633043)

* Wed Jan 19 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.9-2
- Fix to honor the user's cert trust preferences (#633043)
- Remove obsoleted patch

* Wed Jan 12 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.9-1
- Update to 3.12.9

* Mon Dec 27 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.9-0.1.beta2
- Rebuilt according to fedora pre-release package naming guidelines

* Fri Dec 10 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.8.99.2-1
- Update to NSS_3_12_9_BETA2
- Fix libpnsspem crash when cacert dir contains other directories (#642433)

* Wed Dec 08 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.8.99.1-1
- Update to NSS_3_12_9_BETA1

* Thu Nov 25 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.8-9
- Update pem source tar with fixes for 614532 and 596674
- Remove no longer needed patches

* Fri Nov 05 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.8-8
- Update PayPalEE.cert test certificate which had expired

* Sun Oct 31 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.8-7
- Tell rpm not to verify md5, size, and modtime of configurations file

* Mon Oct 18 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.8-6
- Fix certificates trust order (#643134)
- Apply nss-sysinit-userdb-first.patch last

* Wed Oct 06 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.8-5
- Move triggerpostun -n nss-sysinit script ahead of the other ones (#639248)

* Tue Oct 05 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.8-4
- Fix invalid %%postun scriptlet (#639248)

* Wed Sep 29 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.8-3
- Replace posttrans sysinit scriptlet with a triggerpostun one (#636787)
- Fix and cleanup the setup-nsssysinit.sh script (#636792, #636801)

* Mon Sep 27 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.8-2
- Add posttrans scriptlet (#636787)

* Thu Sep 23 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.8-1
- Update to 3.12.8
- Prevent disabling of nss-sysinit on package upgrade (#636787)
- Create pkcs11.txt with correct permissions regardless of umask (#636792)
- Setup-nsssysinit.sh reports whether nss-sysinit is turned on or off (#636801)
- Added provides pkcs11-devel-static to comply with packaging guidelines (#609612)

* Sat Sep 18 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.7.99.4-1
- NSS 3.12.8 RC0

* Sun Sep 05 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.7.99.3-2
- Fix nss-util_version and nss_softokn_version required to be 3.12.7.99.3

* Sat Sep 04 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.7.99.3-1
- NSS 3.12.8 Beta3
- Fix unclosed comment in renegotiate-transitional.patch

* Sat Aug 28 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.7-3
- Change BuildRequries to available version of nss-util-devel

* Sat Aug 28 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.7-2
- Define NSS_USE_SYSTEM_SQLITE and remove unneeded patch
- Add comments regarding an unversioned provides which triggers rpmlint warning
- Build requires nss-softokn-devel >= 3.12.7

* Mon Aug 16 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.7-1
- Update to 3.12.7

* Sat Aug 14 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.6-12
- Apply the patches to fix rhbz#614532

* Mon Aug 09 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.6-11
- Removed pem sourecs as they are in the cache

* Mon Aug 09 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.6-10
- Add support for PKCS#8 encoded PEM RSA private key files (#614532)

* Sat Jul 31 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.6-9
- Fix nsssysinit to return userdb ahead of systemdb (#603313)

* Tue Jun 08 2010 Dennis Gilmore <dennis@ausil.us> - 3.12.6-8
- Require and BuildRequire >= the listed version not =

* Tue Jun 08 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.6-7
- Require nss-softoken 3.12.6

* Sun Jun 06 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.6-6
- Fix SIGSEGV within CreateObject (#596674)

* Mon Apr 12 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.6-5
- Update pem source tar to pick up the following bug fixes:
- PEM - Allow collect objects to search through all objects
- PEM - Make CopyObject return a new shallow copy
- PEM - Fix memory leak in pem_mdCryptoOperationRSAPriv

* Wed Apr 07 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.6-4
- Update the test cert in the setup phase

* Wed Apr 07 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.6-3
- Add sed to sysinit requires as setup-nsssysinit.sh requires it (#576071)
- Update PayPalEE test cert with unexpired one (#580207)

* Thu Mar 18 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.6-2
- Fix ns.spec to not require nss-softokn (#575001)

* Sat Mar 06 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.6-1.2
- rebuilt with all tests enabled

* Sat Mar 06 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.6-1.1
- Using SSL_RENEGOTIATE_TRANSITIONAL as default while on transition period
- Disabling ssl tests suites until bug 539183 is resolved

* Sat Mar 06 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.6-1
- Update to 3.12.6
- Reactivate all tests
- Patch tools to validate command line options arguments

* Mon Jan 25 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.5-8
- Fix curl related regression and general patch code clean up

* Wed Jan 13 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.5-5
-  retagging

* Tue Jan 12 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.5-1.1
- Fix SIGSEGV on call of NSS_Initialize (#553638)

* Wed Jan 06 2010 Elio Maldonado<emaldona@redhat.com> - 3.12.5-1.13.2
- New version of patch to allow root to modify ystem database (#547860)

* Thu Dec 31 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.5-1.13.1
- Temporarily disabling the ssl tests

* Sat Dec 26 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.5-1.13
- Fix nsssysinit to allow root to modify the nss system database (#547860)

* Fri Dec 25 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.5-1.11
- Fix an error introduced when adapting the patch for rhbz #546211

* Sat Dec 19 2009 Elio maldonado<emaldona@redhat.com> - 3.12.5-1.9
- Remove left over trace statements from nsssysinit patching

* Fri Dec 18 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.5-2.7
- Fix a misconstructed patch

* Thu Dec 17 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.5-1.6
- Fix nsssysinit to enable apps to use system cert store, patch contributed by David Woodhouse (#546221)
- Fix spec so sysinit requires coreutils for post install scriplet (#547067)
- Fix segmentation fault when listing keys or certs in the database, patch contributed by Kamil Dudka (#540387)

* Thu Dec 10 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.5-1.5
- Fix nsssysinit to set the default flags on the crypto module (#545779)
- Remove redundant header from the pem module

* Wed Dec 09 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.5-1.1
- Remove unneeded patch

* Thu Dec 03 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.5-1.1
- Retagging to include missing patch

* Thu Dec 03 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.5-1
- Update to 3.12.5
- Patch to allow ssl/tls clients to interoperate with servers that require renogiation

* Fri Nov 20 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.4-14.1
- Retagging

* Tue Oct 20 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.4-13.1
- Require nss-softoken of same architecture as nss (#527867)
- Merge setup-nsssysinit.sh improvements from F-12 (#527051)

* Sat Oct 03 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.4-13
- User no longer prompted for a password when listing keys an empty system db (#527048)
- Fix setup-nsssysinit to handle more general formats (#527051)

* Sun Sep 27 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.4-12
- Fix syntax error in setup-nsssysinit.sh

* Sun Sep 27 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.4-11
- Fix sysinit to be under mozilla/security/nss/lib

* Sat Sep 26 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.4-10
- Add nss-sysinit activation/deactivation script

* Fri Sep 18 2009 Elio Maldonado<emaldona@redhat.com - 3.12.4-9
- Install blank databases and configuration file for system shared database
- nsssysinit queries system for fips mode before relying on environment variable

* Thu Sep 10 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.4-8
- Restoring nssutil and -rpath-link to nss-config for now - 522477

* Tue Sep 08 2009 Elio Maldonado<emaldona@redhat.com - 3.12.4-7
- Add the nss-sysinit subpackage

* Tue Sep 08 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.4-6
- Installing shared libraries to %%{_libdir}

* Mon Sep 07 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.4-5
- Retagging to pick up new sources

* Mon Sep 07 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.4-4
- Update pem enabling source tar with latest fixes (509705, 51209)

* Sun Sep 06 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.4-3
- PEM module implements memory management for internal objects - 509705
- PEM module doesn't crash when processing malformed key files - 512019

* Sat Sep 05 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.4-2
- Remove symbolic links to shared libraries from devel - 521155
- No rpath-link in nss-softokn-config

* Tue Sep 01 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.4-1
- Update to 3.12.4

* Mon Aug 31 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.3.99.3-30
- Fix FORTIFY_SOURCE buffer overflows in test suite on ppc and ppc64 - bug 519766
- Fixed requires and buildrequires as per recommendations in spec file review

* Sun Aug 30 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.3.99.3-29
- Restoring patches 2 and 7 as we still compile all sources
- Applying the nss-nolocalsql.patch solves nss-tools sqlite dependency problems

* Sun Aug 30 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.3.99.3-28
- restore require sqlite

* Sat Aug 29 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.3.99.3-27
- Don't require sqlite for nss

* Sat Aug 29 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.3.99.3-26
- Ensure versions in the requires match those used when creating nss.pc

* Fri Aug 28 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.3.99.3-25
- Remove nss-prelink.conf as signed all shared libraries moved to nss-softokn
- Add a temprary hack to nss.pc.in to unblock builds

* Fri Aug 28 2009 Warren Togami <wtogami@redhat.com> - 3.12.3.99.3-24
- caolan's nss.pc patch

* Thu Aug 27 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.3.99.3-23
- Bump the release number for a chained build of nss-util, nss-softokn and nss

* Thu Aug 27 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.3.99.3-22
- Fix nss-config not to include nssutil
- Add BuildRequires on nss-softokn and nss-util since build also runs the test suite

* Thu Aug 27 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.3.99.3-21
- disabling all tests while we investigate a buffer overflow bug

* Thu Aug 27 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.3.99.3-20
- disabling some tests while we investigate a buffer overflow bug - 519766

* Thu Aug 27 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.3.99.3-19
- remove patches that are now in nss-softokn and
- remove spurious exec-permissions for nss.pc per rpmlint
- single requires line in nss.pc.in

* Wed Aug 26 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.3.99.3-18
- Fix BuildRequires: nss-softokn-devel release number

* Wed Aug 26 2009 Elio Maldonado<emaldona@redhat.com - 3.12.3.99.3-17
- fix nss.pc.in to have one single requires line

* Tue Aug 25 2009 Dennis Gilmore <dennis@ausil.us> - 3.12.3.99.3-16
- cleanups for softokn

* Tue Aug 25 2009 Dennis Gilmore <dennis@ausil.us> - 3.12.3.99.3-15
- remove the softokn subpackages

* Mon Aug 24 2009 Dennis Gilmore <dennis@ausil.us> - 3.12.3.99.3-14
- don install the nss-util pkgconfig bits

* Mon Aug 24 2009 Dennis Gilmore <dennis@ausil.us> - 3.12.3.99.3-13
- remove from -devel the 3 headers that ship in nss-util-devel

* Mon Aug 24 2009 Dennis Gilmore <dennis@ausil.us> - 3.12.3.99.3-12
- kill off the nss-util nss-util-devel subpackages

* Sun Aug 23 2009 Elio Maldonado+emaldona@redhat.com - 3.12.3.99.3-11
- split off nss-softokn and nss-util as subpackages with their own rpms
- first phase of splitting nss-softokn and nss-util as their own packages

* Thu Aug 20 2009 Elio Maldonado <emaldona@redhat.com> - 3.12.3.99.3-10
- must install libnssutil3.since nss-util is untagged at the moment
- preserve time stamps when installing various files

* Thu Aug 20 2009 Dennis Gilmore <dennis@ausil.us> - 3.12.3.99.3-9
- dont install libnssutil3.so since its now in nss-util

* Thu Aug 06 2009 Elio Maldonado <emaldona@redhat.com> - 3.12.3.99.3-7.1
- Fix spec file problems uncovered by Fedora_12_Mass_Rebuild

* Sat Jul 25 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 3.12.3.99.3-7
- Rebuilt for https://fedoraproject.org/wiki/Fedora_12_Mass_Rebuild

* Mon Jun 22 2009 Elio Maldonado <emaldona@redhat.com> - 3.12.3.99.3-6
- removed two patch files which are no longer needed and fixed previous change log number
* Mon Jun 22 2009 Elio Maldonado <emaldona@redhat.com> - 3.12.3.99.3-5
- updated pem module incorporates various patches
- fix off-by-one error when computing size to reduce memory leak. (483855)
- fix data type to work on x86_64 systems. (429175)
- fix various memory leaks and free internal objects on module unload. (501080)
- fix to not clone internal objects in collect_objects().  (501118)
- fix to not bypass initialization if module arguments are omitted. (501058)
- fix numerous gcc warnings. (500815)
- fix to support arbitrarily long password while loading a private key. (500180)
- fix memory leak in make_key and memory leaks and return values in pem_mdSession_Login (501191)
* Mon Jun 08 2009 Elio Maldonado <emaldona@redhat.com> - 3.12.3.99.3-4
- add patch for bug 502133 upstream bug 496997
* Fri Jun 05 2009 Kai Engert <kaie@redhat.com> - 3.12.3.99.3-3
- rebuild with higher release number for upgrade sanity
* Fri Jun 05 2009 Kai Engert <kaie@redhat.com> - 3.12.3.99.3-2
- updated to NSS_3_12_4_FIPS1_WITH_CKBI_1_75
* Thu May 07 2009 Kai Engert <kaie@redhat.com> - 3.12.3-7
- re-enable test suite
- add patch for upstream bug 488646 and add newer paypal
  certs in order to make the test suite pass
* Wed May 06 2009 Kai Engert <kaie@redhat.com> - 3.12.3-4
- add conflicts info in order to fix bug 499436
* Tue Apr 14 2009 Kai Engert <kaie@redhat.com> - 3.12.3-3
- ship .chk files instead of running shlibsign at install time
- include .chk file in softokn-freebl subpackage
- add patch for upstream nss bug 488350
* Tue Apr 14 2009 Kai Engert <kaie@redhat.com> - 3.12.3-2
- Update to NSS 3.12.3
* Mon Apr 06 2009 Kai Engert <kaie@redhat.com> - 3.12.2.99.3-7
- temporarily disable the test suite because of bug 494266
* Mon Apr 06 2009 Kai Engert <kaie@redhat.com> - 3.12.2.99.3-6
- fix softokn-freebl dependency for multilib (bug 494122)
* Thu Apr 02 2009 Kai Engert <kaie@redhat.com> - 3.12.2.99.3-5
- introduce separate nss-softokn-freebl package
* Thu Apr 02 2009 Kai Engert <kaie@redhat.com> - 3.12.2.99.3-4
- disable execstack when building freebl
* Tue Mar 31 2009 Kai Engert <kaie@redhat.com> - 3.12.2.99.3-3
- add upstream patch to fix bug 483855
* Tue Mar 31 2009 Kai Engert <kaie@redhat.com> - 3.12.2.99.3-2
- build nspr-less freebl library
* Tue Mar 31 2009 Kai Engert <kaie@redhat.com> - 3.12.2.99.3-1
- Update to NSS_3_12_3_BETA4

* Wed Feb 25 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 3.12.2.0-4
- Rebuilt for https://fedoraproject.org/wiki/Fedora_11_Mass_Rebuild

* Wed Oct 22 2008 Kai Engert <kaie@redhat.com> - 3.12.2.0-3
- update to NSS_3_12_2_RC1
- use system zlib
* Tue Sep 30 2008 Dennis Gilmore <dennis@ausil.us> - 3.12.1.1-4
- add sparc64 to the list of 64 bit arches

* Wed Sep 24 2008 Kai Engert <kaie@redhat.com> - 3.12.1.1-3
- bug 456847, move pkgconfig requirement to devel package
* Fri Sep 05 2008 Kai Engert <kengert@redhat.com> - 3.12.1.1-2
- Update to NSS_3_12_1_RC2
* Fri Aug 22 2008 Kai Engert <kaie@redhat.com> - 3.12.1.0-2
- NSS 3.12.1 RC1
* Fri Aug 15 2008 Kai Engert <kaie@redhat.com> - 3.12.0.3-7
- fix bug bug 429175 in libpem module
* Tue Aug 05 2008 Kai Engert <kengert@redhat.com> - 3.12.0.3-6
- bug 456847, add Requires: pkgconfig
* Tue Jun 24 2008 Kai Engert <kengert@redhat.com> - 3.12.0.3-3
- nss package should own /etc/prelink.conf.d folder, rhbz#452062
- use upstream patch to fix test suite abort
* Mon Jun 02 2008 Kai Engert <kengert@redhat.com> - 3.12.0.3-2
- Update to NSS_3_12_RC4
* Mon Apr 14 2008 Kai Engert <kengert@redhat.com> - 3.12.0.1-1
- Update to NSS_3_12_RC2
* Thu Mar 20 2008 Jesse Keating <jkeating@redhat.com> - 3.11.99.5-2
- Zapping old Obsoletes/Provides.  No longer needed, causes multilib headache.
* Mon Mar 17 2008 Kai Engert <kengert@redhat.com> - 3.11.99.5-1
- Update to NSS_3_12_BETA3
* Fri Feb 22 2008 Kai Engert <kengert@redhat.com> - 3.11.99.4-1
- NSS 3.12 Beta 2
- Use /usr/lib{64} as devel libdir, create symbolic links.
* Sat Feb 16 2008 Kai Engert <kengert@redhat.com> - 3.11.99.3-6
- Apply upstream patch for bug 417664, enable test suite on pcc.
* Fri Feb 15 2008 Kai Engert <kengert@redhat.com> - 3.11.99.3-5
- Support concurrent runs of the test suite on a single build host.
* Thu Feb 14 2008 Kai Engert <kengert@redhat.com> - 3.11.99.3-4
- disable test suite on ppc
* Thu Feb 14 2008 Kai Engert <kengert@redhat.com> - 3.11.99.3-3
- disable test suite on ppc64

* Thu Feb 14 2008 Kai Engert <kengert@redhat.com> - 3.11.99.3-2
- Build against gcc 4.3.0, use workaround for bug 432146
- Run the test suite after the build and abort on failures.

* Thu Jan 24 2008 Kai Engert <kengert@redhat.com> - 3.11.99.3-1
* NSS 3.12 Beta 1

* Mon Jan 07 2008 Kai Engert <kengert@redhat.com> - 3.11.99.2b-3
- move .so files to /lib

* Wed Dec 12 2007 Kai Engert <kengert@redhat.com> - 3.11.99.2b-2
- NSS 3.12 alpha 2b

* Mon Dec 03 2007 Kai Engert <kengert@redhat.com> - 3.11.99.2-2
- upstream patches to avoid calling netstat for random data

* Wed Nov 07 2007 Kai Engert <kengert@redhat.com> - 3.11.99.2-1
- NSS 3.12 alpha 2

* Wed Oct 10 2007 Kai Engert <kengert@redhat.com> - 3.11.7-10
- Add /etc/prelink.conf.d/nss-prelink.conf in order to blacklist
  our signed libraries and protect them from modification.

* Thu Sep 06 2007 Rob Crittenden <rcritten@redhat.com> - 3.11.7-9
- Fix off-by-one error in the PEM module

* Thu Sep 06 2007 Kai Engert <kengert@redhat.com> - 3.11.7-8
- fix a C++ mode compilation error

* Wed Sep 05 2007 Bob Relyea <rrelyea@redhat.com> - 3.11.7-7
- Add 3.12 ckfw and libnsspem

* Tue Aug 28 2007 Kai Engert <kengert@redhat.com> - 3.11.7-6
- Updated license tag

* Wed Jul 11 2007 Kai Engert <kengert@redhat.com> - 3.11.7-5
- Ensure the workaround for mozilla bug 51429 really get's built.

* Mon Jun 18 2007 Kai Engert <kengert@redhat.com> - 3.11.7-4
- Better approach to ship freebl/softokn based on 3.11.5
- Remove link time dependency on softokn

* Sun Jun 10 2007 Kai Engert <kengert@redhat.com> - 3.11.7-3
- Fix unowned directories, rhbz#233890

* Fri Jun 01 2007 Kai Engert <kengert@redhat.com> - 3.11.7-2
- Update to 3.11.7, but freebl/softokn remain at 3.11.5.
- Use a workaround to avoid mozilla bug 51429.

* Fri Mar 02 2007 Kai Engert <kengert@redhat.com> - 3.11.5-2
- Fix rhbz#230545, failure to enable FIPS mode
- Fix rhbz#220542, make NSS more tolerant of resets when in the
  middle of prompting for a user password.

* Sat Feb 24 2007 Kai Engert <kengert@redhat.com> - 3.11.5-1
- Update to 3.11.5
- This update fixes two security vulnerabilities with SSL 2
- Do not use -rpath link option
- Added several unsupported tools to tools package

* Tue Jan  9 2007 Bob Relyea <rrelyea@redhat.com> - 3.11.4-4
- disable ECC, cleanout dead code

* Tue Nov 28 2006 Kai Engert <kengert@redhat.com> - 3.11.4-1
- Update to 3.11.4

* Thu Sep 14 2006 Kai Engert <kengert@redhat.com> - 3.11.3-2
- Revert the attempt to require latest NSPR, as it is not yet available
  in the build infrastructure.

* Thu Sep 14 2006 Kai Engert <kengert@redhat.com> - 3.11.3-1
- Update to 3.11.3

* Thu Aug 03 2006 Kai Engert <kengert@redhat.com> - 3.11.2-2
- Add /etc/pki/nssdb

* Wed Jul 12 2006 Jesse Keating <jkeating@redhat.com> - 3.11.2-1.1
- rebuild

* Fri Jun 30 2006 Kai Engert <kengert@redhat.com> - 3.11.2-1
- Update to 3.11.2
- Enable executable bit on shared libs, also fixes debug info.

* Wed Jun 14 2006 Kai Engert <kengert@redhat.com> - 3.11.1-2
- Enable Elliptic Curve Cryptography (ECC)

* Fri May 26 2006 Kai Engert <kengert@redhat.com> - 3.11.1-1
- Update to 3.11.1
- Include upstream patch to limit curves

* Wed Feb 15 2006 Kai Engert <kengert@redhat.com> - 3.11-4
- add --noexecstack when compiling assembler on x86_64

* Fri Feb 10 2006 Jesse Keating <jkeating@redhat.com> - 3.11-3.2
- bump again for double-long bug on ppc(64)

* Tue Feb 07 2006 Jesse Keating <jkeating@redhat.com> - 3.11-3.1
- rebuilt for new gcc4.1 snapshot and glibc changes

* Thu Jan 19 2006 Ray Strode <rstrode@redhat.com> 3.11-3
- rebuild

* Fri Dec 16 2005 Christopher Aillon <caillon@redhat.com> 3.11-2
- Update file list for the devel packages

* Thu Dec 15 2005 Christopher Aillon <caillon@redhat.com> 3.11-1
- Update to 3.11

* Thu Dec 15 2005 Christopher Aillon <caillon@redhat.com> 3.11-0.cvs.2
- Add patch to allow building on ppc*
- Update the pkgconfig file to Require nspr

* Thu Dec 15 2005 Christopher Aillon <caillon@redhat.com> 3.11-0.cvs
- Initial import into Fedora Core, based on a CVS snapshot of
  the NSS_3_11_RTM tag
- Fix up the pkcs11-devel subpackage to contain the proper headers
- Build with RPM_OPT_FLAGS
- No need to have rpath of /usr/lib in the pc file

* Thu Dec 15 2005 Kai Engert <kengert@redhat.com>
- Adressed review comments by Wan-Teh Chang, Bob Relyea,
  Christopher Aillon.

* Sat Jul  9 2005 Rob Crittenden <rcritten@redhat.com> 3.10-1
- Initial build
