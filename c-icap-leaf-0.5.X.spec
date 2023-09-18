%define modn      c_icap
%define cicapname c-icap

Summary:          Leaf ICAP service
License:          Proprietary
Summary:          ICAP leaf service
Name:             c-icap-leaf
Version:          0.5.X
Release:          2%{?dist}

Source0:          http://sourceforge.net/projects/c-icap/files/c-icap/0.5.x/%{name}-%{version}.tar.xz
URL:              http://%{name}.sourceforge.net/
Source1:          c-icap.leaf.defaults

Requires:         c-icap-libs c-icap mariadb mariadb-connector-c
BuildRequires:    systemd
BuildRequires:    gdbm-devel openldap-devel perl-devel c-icap-devel
BuildRequires:    mariadb-devel mariadb-connector-c-devel

%description 
The %{name} package contains the static libraries and objects to enable
HTTPS/HTTP SSL decoding and web page archival.

%prep
%setup -q -n %{name}-%{version}

%build
%configure \
	CFLAGS="${RPM_OPT_FLAGS} -fno-strict-aliasing" \
	--sysconfdir=%{_sysconfdir}/%{name}            \
	--enable-shared                                \
	--enable-static                                \
	--enable-lib-compat                            \
	--with-perl                                    \
	--with-zlib                                    \
	--with-bdb                                     \
	--with-ldap                                    \
        --enable-large-files				
#       --disable-poll
#	--enable-ipv6  # net.ipv6.bindv6only not supported

%{__make} %{?_smp_mflags}

%install
[ -n "%{buildroot}" -a "%{buildroot}" != "/" ] && %{__rm} -rf %{buildroot}
%{__make} \
	DESTDIR=%{buildroot} \
	install
%{__install} -D -p -m 0644 %{SOURCE1} %{buildroot}%{_sysconfdir}/%{cicapname}/leaf.conf
%{__rm}      -f                   %{buildroot}%{_libdir}/lib*.so.{?,??}

%pre

%post

%preun

%postun

%files
%defattr(-,root,root)
%attr(640,root,%{cicapname}) %config(noreplace) %{_sysconfdir}/%{cicapname}/*.conf
%{_libdir}/%{modn}/srv_leaf.so
%{_libdir}/%{modn}/srv_leaf.*a
%{_libdir}/%{modn}/srv_leafinfo.so
%{_libdir}/%{modn}/srv_leafinfo.*a

%changelog
