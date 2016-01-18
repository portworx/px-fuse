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

%if 0%{?kernalpath:1}
export KERNALPATH="%kernalpath"
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
cd -

%check

%clean
/bin/rm -rf $RPM_BUILD_ROOT

%files -f %{name}.files
%defattr(-,root,root,0755)

%pre

%post

if [ -e /%{name}.files ]; then   
   mkdir -p /lib/modules/$(uname -r)/extra;
   for fl in $(cat /%{name}.files); do cp -a $fl /lib/modules/$(uname -r)/extra; done;      
   [ -e /etc/modules ] && /bin/egrep -q '^%{name}$' /etc/modules || echo -e '%{name}\n' >> /etc/modules
   /bin/rm /%{name}.files
   /usr/sbin/depmod -a 
   /usr/sbin/modprobe %{name}
   fi
fi

%postun
#if [ $1 = 0 ]; then
#fi
/bin/rm -f /lib/modules/$(uname -r)/extra/%{name}.ko

%preun
#if [ $1 = 0 ]; then
#fi

%changelog
* Sat Jan 16 2016 jvinod
- Initial spec file creation
