# Enable building from outside build system
%{!?pxrelease:%define pxrelease 0.0}
%{!?release:%define release 0}
%{!?rpmdescription: %define rpmdescription This package contains %summary.}

Name: %name
Version: %pxrelease
Release: %release
Summary: %summary
Group: PX Runtime Environment
License: Proprietary
Source: %{name}-%{version}-%{release}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
Obsoletes: %name
autoreqprov: no

%if 0%{?required:1}
Requires: %required
%endif

%if 0%{?required_rpms:1}
BuildRequires: %required_rpms
%endif

%description
  %rpmdescription

%prep
%setup -n %specsrcdir

%build

%if 0%{?kernelpath:1}
export KERNELPATH="%kernelpath"
%endif

%if 0%{?kernelother:1}
export KERNELOTHER="%kernelother"
%endif

autoreconf
./configure
make clean all 

%install
rm -rf $RPM_BUILD_ROOT
INSTALL_MOD_PATH=$RPM_BUILD_ROOT make install

LOC=`pwd`
cd $RPM_BUILD_ROOT
# Create file list for rpm install
find . -name px.ko -exec echo \"{}\" \; | sed 's/^"\./"/' > $LOC/%{name}.files
cp -a $LOC/%{name}.files .
echo /%{name}.files >> $LOC/%{name}.files
MDIR=$(cat $LOC/%{name}.files | /bin/egrep px.ko | /bin/sed -e 's/\/extra\/.*//' -e 's/"//g' -e 's/^\/lib/lib/' | /usr/bin/tr -d '[:space:]')
[ -d "${MDIR}" ] && for fl in $(ls ${MDIR}/*); do [ ! -d ${fl} ] && /bin/rm -f ${fl}; done
cd -

%check

%clean
/bin/rm -rf $RPM_BUILD_ROOT

%files -f %{name}.files
%defattr(-,root,root,0755)

%pre

%post

lsmod | egrep -q '^%{name} '
[ $? -eq 0 ] && rmmod %{name}

if [ -e /%{name}.files ]; then 
   MDIR="/lib/modules/$(uname -r)/extra"
   mkdir -p ${MDIR}
   FILES=$(cat /%{name}.files| /bin/egrep -v %{name}.files | /bin/sed -e 's/"//g')
   for fl in ${FILES}; do echo $fl | /bin/egrep -q ${MDIR} || cp -af $fl ${MDIR}; done;      
   [ -e /etc/modules ] && /bin/egrep -q '^%{name}$' /etc/modules || echo -e '%{name}' >> /etc/modules
   [ -d /etc/modules-load.d -a ! -e /etc/modules-load.d/px.conf ] && echo -e '%{name}' > /etc/modules-load.d/px.conf
   depmod -a
   modprobe %{name}
fi

%postun

POSTUN=$1

[ "${POSTUN}" == "purge" -o "${POSTUN}" == "remove" ] && POSTUN=0

if [ "${POSTUN}" == "0" ]; then
    lsmod | egrep -q '^%{name} '
    [ $? -eq 0 ] && rmmod %{name}

    MODCONF=/etc/modules
    if [ -e ${MODCONF} ]; then
	/bin/egrep -q '^%{name}$' ${MODCONF}
	if [ $? -eq 0 ]; then
	    cat ${MODCONF} | egrep -v '^%{name}$' > ${MODCONF}.$$
	    /bin/mv ${MODCONF}.$$ ${MODCONF}
	fi
    fi

    [ -e /etc/modules-load.d/px.conf ] && /bin/rm -f /etc/modules-load.d/px.conf

    /bin/rm -f /lib/modules/$(uname -r)/extra/%{name}.ko
fi

%preun
#if [ $1 = 0 ]; then
#fi

%changelog
* Sat Jan 16 2016 jvinod
- Initial spec file creation
