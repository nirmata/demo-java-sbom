# demo-java-sbom

Demo of Java SBOM verification for different JDK / JRE 

## Checking SBOMs

Newer Java versions have a `jrt-fs` that contains information on the vendor:

```json
    {
      "id": "ade8b7bfaa7d1871",
      "name": "jrt-fs",
      "version": "17.0.13",
      "type": "java-archive",
      "foundBy": "java-archive-cataloger",
      "locations": [
        {
          "path": "/usr/lib/jvm/java-17-amazon-corretto/lib/jrt-fs.jar",
          "layerID": "sha256:e71d1c13c6c83d7462ac9547188722b5dbbbfdf6f108b27f675b4929b5cc9f0a",
          "accessPath": "/usr/lib/jvm/java-17-amazon-corretto/lib/jrt-fs.jar",
          "annotations": {
            "evidence": "primary"
          }
        }
      ],
      "licenses": [],
      "language": "java",
      "cpes": [ 
        // trimmed ..
      ],
      "purl": "pkg:maven/jrt-fs/jrt-fs@17.0.13",
      "metadataType": "java-archive",
      "metadata": {
        "virtualPath": "/usr/lib/jvm/java-17-amazon-corretto/lib/jrt-fs.jar",
        "manifest": {
          "main": [
            {
              "key": "Manifest-Version",
              "value": "1.0"
            },
            {
              "key": "Specification-Title",
              "value": "Java Platform API Specification"
            },
            {
              "key": "Specification-Version",
              "value": "17"
            },
            {
              "key": "Specification-Vendor",
              "value": "Oracle Corporation"
            },
            {
              "key": "Implementation-Title",
              "value": "Java Runtime Environment"
            },
            {
              "key": "Implementation-Version",
              "value": "17.0.13"
            },
            {
              "key": "Implementation-Vendor",
              "value": "Amazon.com Inc."
            },
            {
              "key": "Created-By",
              "value": "17.0.12 (Amazon.com Inc.)"
            }
          ]
        },

        // trimmed ...
      }
    }
```

Package URL's for different images. 

```
cat openjdk11.json | jq ".artifacts[].purl"

"pkg:deb/debian/adduser@3.118?arch=all&distro=debian-11"
"pkg:deb/debian/apt@2.2.4?arch=arm64&distro=debian-11"
"pkg:deb/debian/base-files@11.1%2Bdeb11u4?arch=arm64&distro=debian-11"
"pkg:deb/debian/base-passwd@3.5.51?arch=arm64&distro=debian-11"
"pkg:deb/debian/bash@5.1-2%2Bdeb11u1?arch=arm64&distro=debian-11"
"pkg:deb/debian/bsdutils@1:2.36.1-8%2Bdeb11u1?arch=arm64&upstream=util-linux%402.36.1-8%2Bdeb11u1&distro=debian-11"
"pkg:deb/debian/ca-certificates@20210119?arch=all&distro=debian-11"
"pkg:deb/debian/coreutils@8.32-4?arch=arm64&distro=debian-11"
"pkg:deb/debian/dash@0.5.11%2Bgit20200708%2Bdd9ef66-5?arch=arm64&distro=debian-11"
"pkg:deb/debian/debconf@1.5.77?arch=all&distro=debian-11"
"pkg:deb/debian/debian-archive-keyring@2021.1.1?arch=all&distro=debian-11"
"pkg:deb/debian/debianutils@4.11.2?arch=arm64&distro=debian-11"
"pkg:deb/debian/diffutils@1:3.7-5?arch=arm64&distro=debian-11"
"pkg:deb/debian/dpkg@1.20.11?arch=arm64&distro=debian-11"
"pkg:deb/debian/e2fsprogs@1.46.2-2?arch=arm64&distro=debian-11"
"pkg:deb/debian/findutils@4.8.0-1?arch=arm64&distro=debian-11"
"pkg:deb/debian/gcc-10-base@10.2.1-6?arch=arm64&upstream=gcc-10&distro=debian-11"
"pkg:deb/debian/gcc-9-base@9.3.0-22?arch=arm64&upstream=gcc-9&distro=debian-11"
"pkg:deb/debian/gpgv@2.2.27-2%2Bdeb11u2?arch=arm64&upstream=gnupg2&distro=debian-11"
"pkg:deb/debian/grep@3.6-1?arch=arm64&distro=debian-11"
"pkg:deb/debian/gzip@1.10-4%2Bdeb11u1?arch=arm64&distro=debian-11"
"pkg:deb/debian/hostname@3.23?arch=arm64&distro=debian-11"
"pkg:deb/debian/init-system-helpers@1.60?arch=all&distro=debian-11"
"pkg:maven/jrt-fs/jrt-fs@11.0.16"
"pkg:deb/debian/libacl1@2.2.53-10?arch=arm64&upstream=acl&distro=debian-11"
"pkg:deb/debian/libapt-pkg6.0@2.2.4?arch=arm64&upstream=apt&distro=debian-11"
"pkg:deb/debian/libattr1@1:2.4.48-6?arch=arm64&upstream=attr&distro=debian-11"
"pkg:deb/debian/libaudit-common@1:3.0-2?arch=all&upstream=audit&distro=debian-11"
"pkg:deb/debian/libaudit1@1:3.0-2?arch=arm64&upstream=audit&distro=debian-11"
"pkg:deb/debian/libblkid1@2.36.1-8%2Bdeb11u1?arch=arm64&upstream=util-linux&distro=debian-11"
"pkg:deb/debian/libbz2-1.0@1.0.8-4?arch=arm64&upstream=bzip2&distro=debian-11"
"pkg:deb/debian/libc-bin@2.31-13%2Bdeb11u3?arch=arm64&upstream=glibc&distro=debian-11"
"pkg:deb/debian/libc6@2.31-13%2Bdeb11u3?arch=arm64&upstream=glibc&distro=debian-11"
"pkg:deb/debian/libcap-ng0@0.7.9-2.2%2Bb1?arch=arm64&upstream=libcap-ng%400.7.9-2.2&distro=debian-11"
"pkg:deb/debian/libcom-err2@1.46.2-2?arch=arm64&upstream=e2fsprogs&distro=debian-11"
"pkg:deb/debian/libcrypt1@1:4.4.18-4?arch=arm64&upstream=libxcrypt&distro=debian-11"
"pkg:deb/debian/libdb5.3@5.3.28%2Bdfsg1-0.8?arch=arm64&upstream=db5.3&distro=debian-11"
"pkg:deb/debian/libdebconfclient0@0.260?arch=arm64&upstream=cdebconf&distro=debian-11"
"pkg:deb/debian/libext2fs2@1.46.2-2?arch=arm64&upstream=e2fsprogs&distro=debian-11"
"pkg:deb/debian/libffi7@3.3-6?arch=arm64&upstream=libffi&distro=debian-11"
"pkg:deb/debian/libgcc-s1@10.2.1-6?arch=arm64&upstream=gcc-10&distro=debian-11"
"pkg:deb/debian/libgcrypt20@1.8.7-6?arch=arm64&distro=debian-11"
"pkg:deb/debian/libgmp10@2:6.2.1%2Bdfsg-1%2Bdeb11u1?arch=arm64&upstream=gmp&distro=debian-11"
"pkg:deb/debian/libgnutls30@3.7.1-5%2Bdeb11u1?arch=arm64&upstream=gnutls28&distro=debian-11"
"pkg:deb/debian/libgpg-error0@1.38-2?arch=arm64&upstream=libgpg-error&distro=debian-11"
"pkg:deb/debian/libgssapi-krb5-2@1.18.3-6%2Bdeb11u1?arch=arm64&upstream=krb5&distro=debian-11"
"pkg:deb/debian/libhogweed6@3.7.3-1?arch=arm64&upstream=nettle&distro=debian-11"
"pkg:deb/debian/libidn2-0@2.3.0-5?arch=arm64&upstream=libidn2&distro=debian-11"
"pkg:deb/debian/libk5crypto3@1.18.3-6%2Bdeb11u1?arch=arm64&upstream=krb5&distro=debian-11"
"pkg:deb/debian/libkeyutils1@1.6.1-2?arch=arm64&upstream=keyutils&distro=debian-11"
"pkg:deb/debian/libkrb5-3@1.18.3-6%2Bdeb11u1?arch=arm64&upstream=krb5&distro=debian-11"
"pkg:deb/debian/libkrb5support0@1.18.3-6%2Bdeb11u1?arch=arm64&upstream=krb5&distro=debian-11"
"pkg:deb/debian/liblz4-1@1.9.3-2?arch=arm64&upstream=lz4&distro=debian-11"
"pkg:deb/debian/liblzma5@5.2.5-2.1~deb11u1?arch=arm64&upstream=xz-utils&distro=debian-11"
"pkg:deb/debian/libmount1@2.36.1-8%2Bdeb11u1?arch=arm64&upstream=util-linux&distro=debian-11"
"pkg:deb/debian/libnettle8@3.7.3-1?arch=arm64&upstream=nettle&distro=debian-11"
"pkg:deb/debian/libnsl2@1.3.0-2?arch=arm64&upstream=libnsl&distro=debian-11"
"pkg:deb/debian/libp11-kit0@0.23.22-1?arch=arm64&upstream=p11-kit&distro=debian-11"
"pkg:deb/debian/libpam-modules@1.4.0-9%2Bdeb11u1?arch=arm64&upstream=pam&distro=debian-11"
"pkg:deb/debian/libpam-modules-bin@1.4.0-9%2Bdeb11u1?arch=arm64&upstream=pam&distro=debian-11"
"pkg:deb/debian/libpam-runtime@1.4.0-9%2Bdeb11u1?arch=all&upstream=pam&distro=debian-11"
"pkg:deb/debian/libpam0g@1.4.0-9%2Bdeb11u1?arch=arm64&upstream=pam&distro=debian-11"
"pkg:deb/debian/libpcre2-8-0@10.36-2?arch=arm64&upstream=pcre2&distro=debian-11"
"pkg:deb/debian/libpcre3@2:8.39-13?arch=arm64&upstream=pcre3&distro=debian-11"
"pkg:deb/debian/libseccomp2@2.5.1-1%2Bdeb11u1?arch=arm64&upstream=libseccomp&distro=debian-11"
"pkg:deb/debian/libselinux1@3.1-3?arch=arm64&upstream=libselinux&distro=debian-11"
"pkg:deb/debian/libsemanage-common@3.1-1?arch=all&upstream=libsemanage&distro=debian-11"
"pkg:deb/debian/libsemanage1@3.1-1%2Bb2?arch=arm64&upstream=libsemanage%403.1-1&distro=debian-11"
"pkg:deb/debian/libsepol1@3.1-1?arch=arm64&upstream=libsepol&distro=debian-11"
"pkg:deb/debian/libsmartcols1@2.36.1-8%2Bdeb11u1?arch=arm64&upstream=util-linux&distro=debian-11"
"pkg:deb/debian/libss2@1.46.2-2?arch=arm64&upstream=e2fsprogs&distro=debian-11"
"pkg:deb/debian/libssl1.1@1.1.1n-0%2Bdeb11u3?arch=arm64&upstream=openssl&distro=debian-11"
"pkg:deb/debian/libstdc%2B%2B6@10.2.1-6?arch=arm64&upstream=gcc-10&distro=debian-11"
"pkg:deb/debian/libsystemd0@247.3-7?arch=arm64&upstream=systemd&distro=debian-11"
"pkg:deb/debian/libtasn1-6@4.16.0-2?arch=arm64&distro=debian-11"
"pkg:deb/debian/libtinfo6@6.2%2B20201114-2?arch=arm64&upstream=ncurses&distro=debian-11"
"pkg:deb/debian/libtirpc-common@1.3.1-1?arch=all&upstream=libtirpc&distro=debian-11"
"pkg:deb/debian/libtirpc3@1.3.1-1?arch=arm64&upstream=libtirpc&distro=debian-11"
"pkg:deb/debian/libudev1@247.3-7?arch=arm64&upstream=systemd&distro=debian-11"
"pkg:deb/debian/libunistring2@0.9.10-4?arch=arm64&upstream=libunistring&distro=debian-11"
"pkg:deb/debian/libuuid1@2.36.1-8%2Bdeb11u1?arch=arm64&upstream=util-linux&distro=debian-11"
"pkg:deb/debian/libxxhash0@0.8.0-2?arch=arm64&upstream=xxhash&distro=debian-11"
"pkg:deb/debian/libzstd1@1.4.8%2Bdfsg-2.1?arch=arm64&upstream=libzstd&distro=debian-11"
"pkg:deb/debian/login@1:4.8.1-1?arch=arm64&upstream=shadow&distro=debian-11"
"pkg:deb/debian/logsave@1.46.2-2?arch=arm64&upstream=e2fsprogs&distro=debian-11"
"pkg:deb/debian/lsb-base@11.1.0?arch=all&upstream=lsb&distro=debian-11"
"pkg:deb/debian/mawk@1.3.4.20200120-2?arch=arm64&distro=debian-11"
"pkg:deb/debian/mount@2.36.1-8%2Bdeb11u1?arch=arm64&upstream=util-linux&distro=debian-11"
"pkg:deb/debian/ncurses-base@6.2%2B20201114-2?arch=all&upstream=ncurses&distro=debian-11"
"pkg:deb/debian/ncurses-bin@6.2%2B20201114-2?arch=arm64&upstream=ncurses&distro=debian-11"
"pkg:generic/oracle/openjdk@11.0.16"
"pkg:deb/debian/openssl@1.1.1n-0%2Bdeb11u3?arch=arm64&distro=debian-11"
"pkg:deb/debian/p11-kit@0.23.22-1?arch=arm64&distro=debian-11"
"pkg:deb/debian/p11-kit-modules@0.23.22-1?arch=arm64&upstream=p11-kit&distro=debian-11"
"pkg:deb/debian/passwd@1:4.8.1-1?arch=arm64&upstream=shadow&distro=debian-11"
"pkg:deb/debian/perl-base@5.32.1-4%2Bdeb11u2?arch=arm64&upstream=perl&distro=debian-11"
"pkg:deb/debian/sed@4.7-1?arch=arm64&distro=debian-11"
"pkg:deb/debian/sysvinit-utils@2.96-7%2Bdeb11u1?arch=arm64&upstream=sysvinit&distro=debian-11"
"pkg:deb/debian/tar@1.34%2Bdfsg-1?arch=arm64&distro=debian-11"
"pkg:deb/debian/tzdata@2021a-1%2Bdeb11u4?arch=all&distro=debian-11"
"pkg:deb/debian/util-linux@2.36.1-8%2Bdeb11u1?arch=arm64&distro=debian-11"
"pkg:deb/debian/zlib1g@1:1.2.11.dfsg-2%2Bdeb11u1?arch=arm64&upstream=zlib&distro=debian-11"
```

```

cat correto17.json | jq ".artifacts[].purl"

"pkg:pypi/amazon-linux-extras@2.0.3"
"pkg:rpm/amzn/amazon-linux-extras@2.0.3-1.amzn2?arch=noarch&upstream=amazon-linux-extras-2.0.3-1.amzn2.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/basesystem@10.0-7.amzn2.0.1?arch=noarch&upstream=basesystem-10.0-7.amzn2.0.1.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/bash@4.2.46-34.amzn2?arch=aarch64&upstream=bash-4.2.46-34.amzn2.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/bzip2-libs@1.0.6-13.amzn2.0.3?arch=aarch64&upstream=bzip2-1.0.6-13.amzn2.0.3.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/ca-certificates@2023.2.68-1.amzn2.0.1?arch=noarch&upstream=ca-certificates-2023.2.68-1.amzn2.0.1.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/chkconfig@1.7.4-1.amzn2.0.2?arch=aarch64&upstream=chkconfig-1.7.4-1.amzn2.0.2.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/coreutils@8.22-24.amzn2?arch=aarch64&upstream=coreutils-8.22-24.amzn2.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/cpio@2.12-11.amzn2.0.1?arch=aarch64&upstream=cpio-2.12-11.amzn2.0.1.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/curl@8.3.0-1.amzn2.0.7?arch=aarch64&upstream=curl-8.3.0-1.amzn2.0.7.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/cyrus-sasl-lib@2.1.26-24.amzn2.0.1?arch=aarch64&upstream=cyrus-sasl-2.1.26-24.amzn2.0.1.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/dejavu-fonts-common@2.33-6.amzn2?arch=noarch&upstream=dejavu-fonts-2.33-6.amzn2.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/dejavu-sans-fonts@2.33-6.amzn2?arch=noarch&upstream=dejavu-fonts-2.33-6.amzn2.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/diffutils@3.3-5.amzn2?arch=aarch64&upstream=diffutils-3.3-5.amzn2.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/elfutils-libelf@0.176-2.amzn2.0.2?arch=aarch64&upstream=elfutils-0.176-2.amzn2.0.2.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/expat@2.1.0-15.amzn2.0.3?arch=aarch64&upstream=expat-2.1.0-15.amzn2.0.3.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/file-libs@5.11-36.amzn2.0.1?arch=aarch64&upstream=file-5.11-36.amzn2.0.1.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/filesystem@3.2-25.amzn2.0.4?arch=aarch64&upstream=filesystem-3.2-25.amzn2.0.4.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/findutils@4.5.11-6.amzn2?arch=aarch64&epoch=1&upstream=findutils-4.5.11-6.amzn2.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/fontconfig@2.13.0-4.3.amzn2?arch=aarch64&upstream=fontconfig-2.13.0-4.3.amzn2.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/fontpackages-filesystem@1.44-8.amzn2?arch=noarch&upstream=fontpackages-1.44-8.amzn2.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/freetype@2.8-14.amzn2.1.2?arch=aarch64&upstream=freetype-2.8-14.amzn2.1.2.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/gawk@4.0.2-4.amzn2.1.3?arch=aarch64&upstream=gawk-4.0.2-4.amzn2.1.3.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/gdbm@1.13-6.amzn2.0.2?arch=aarch64&epoch=1&upstream=gdbm-1.13-6.amzn2.0.2.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/glib2@2.56.1-9.amzn2.0.8?arch=aarch64&upstream=glib2-2.56.1-9.amzn2.0.8.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/glibc@2.26-64.amzn2.0.2?arch=aarch64&upstream=glibc-2.26-64.amzn2.0.2.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/glibc-common@2.26-64.amzn2.0.2?arch=aarch64&upstream=glibc-2.26-64.amzn2.0.2.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/glibc-langpack-en@2.26-64.amzn2.0.2?arch=aarch64&upstream=glibc-2.26-64.amzn2.0.2.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/glibc-minimal-langpack@2.26-64.amzn2.0.2?arch=aarch64&upstream=glibc-2.26-64.amzn2.0.2.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/gmp@6.0.0-15.amzn2.0.3?arch=aarch64&epoch=1&upstream=gmp-6.0.0-15.amzn2.0.3.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/gnupg2@2.0.22-5.amzn2.0.5?arch=aarch64&upstream=gnupg2-2.0.22-5.amzn2.0.5.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/gpg-pubkey@b04f24e3-5de94a19?distro=amzn-2"
"pkg:rpm/amzn/gpg-pubkey@c87f5b1a-593863f8?distro=amzn-2"
"pkg:rpm/amzn/gpgme@1.3.2-5.amzn2.0.2?arch=aarch64&upstream=gpgme-1.3.2-5.amzn2.0.2.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/grep@2.20-3.amzn2.0.2?arch=aarch64&upstream=grep-2.20-3.amzn2.0.2.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/info@5.1-5.amzn2?arch=aarch64&upstream=texinfo-5.1-5.amzn2.src.rpm&distro=amzn-2"
"pkg:pypi/iniparse@0.4"
"pkg:rpm/amzn/java-17-amazon-corretto-devel@17.0.13.11-1?arch=aarch64&epoch=1&upstream=java-17-amazon-corretto-devel-17.0.13.11-1.src.rpm&distro=amzn-2"
"pkg:maven/jrt-fs/jrt-fs@17.0.13"
"pkg:rpm/amzn/keyutils-libs@1.5.8-3.amzn2.0.2?arch=aarch64&upstream=keyutils-1.5.8-3.amzn2.0.2.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/krb5-libs@1.15.1-55.amzn2.2.8?arch=aarch64&upstream=krb5-1.15.1-55.amzn2.2.8.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/libacl@2.2.51-14.amzn2?arch=aarch64&upstream=acl-2.2.51-14.amzn2.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/libassuan@2.1.0-3.amzn2.0.2?arch=aarch64&upstream=libassuan-2.1.0-3.amzn2.0.2.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/libattr@2.4.46-12.amzn2.0.2?arch=aarch64&upstream=attr-2.4.46-12.amzn2.0.2.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/libblkid@2.30.2-2.amzn2.0.11?arch=aarch64&upstream=util-linux-2.30.2-2.amzn2.0.11.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/libcap@2.54-1.amzn2.0.2?arch=aarch64&upstream=libcap-2.54-1.amzn2.0.2.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/libcom_err@1.42.9-19.amzn2.0.1?arch=aarch64&upstream=e2fsprogs-1.42.9-19.amzn2.0.1.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/libcrypt@2.26-64.amzn2.0.2?arch=aarch64&upstream=glibc-2.26-64.amzn2.0.2.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/libcurl@8.3.0-1.amzn2.0.7?arch=aarch64&upstream=curl-8.3.0-1.amzn2.0.7.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/libdb@5.3.21-24.amzn2.0.5?arch=aarch64&upstream=libdb-5.3.21-24.amzn2.0.5.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/libdb-utils@5.3.21-24.amzn2.0.5?arch=aarch64&upstream=libdb-5.3.21-24.amzn2.0.5.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/libffi@3.0.13-18.amzn2.0.2?arch=aarch64&upstream=libffi-3.0.13-18.amzn2.0.2.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/libgcc@7.3.1-17.amzn2?arch=aarch64&upstream=gcc-7.3.1-17.amzn2.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/libgcrypt@1.5.3-14.amzn2.0.3?arch=aarch64&upstream=libgcrypt-1.5.3-14.amzn2.0.3.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/libgpg-error@1.12-3.amzn2.0.3?arch=aarch64&upstream=libgpg-error-1.12-3.amzn2.0.3.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/libidn2@2.3.0-1.amzn2.0.3?arch=aarch64&upstream=libidn2-2.3.0-1.amzn2.0.3.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/libmetalink@0.1.3-13.amzn2?arch=aarch64&upstream=libmetalink-0.1.3-13.amzn2.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/libmount@2.30.2-2.amzn2.0.11?arch=aarch64&upstream=util-linux-2.30.2-2.amzn2.0.11.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/libnghttp2@1.41.0-1.amzn2.0.5?arch=aarch64&upstream=nghttp2-1.41.0-1.amzn2.0.5.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/libpng@1.5.13-8.amzn2.0.5?arch=aarch64&epoch=2&upstream=libpng-1.5.13-8.amzn2.0.5.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/libpsl@0.21.5-1.amzn2?arch=aarch64&upstream=libpsl-0.21.5-1.amzn2.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/libselinux@2.5-12.amzn2.0.2?arch=aarch64&upstream=libselinux-2.5-12.amzn2.0.2.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/libsepol@2.5-10.amzn2.0.1?arch=aarch64&upstream=libsepol-2.5-10.amzn2.0.1.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/libssh2@1.4.3-12.amzn2.2.6?arch=aarch64&upstream=libssh2-1.4.3-12.amzn2.2.6.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/libstdc%2B%2B@7.3.1-17.amzn2?arch=aarch64&upstream=gcc-7.3.1-17.amzn2.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/libtasn1@4.10-1.amzn2.0.6?arch=aarch64&upstream=libtasn1-4.10-1.amzn2.0.6.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/libunistring@0.9.3-9.amzn2.0.2?arch=aarch64&upstream=libunistring-0.9.3-9.amzn2.0.2.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/libuuid@2.30.2-2.amzn2.0.11?arch=aarch64&upstream=util-linux-2.30.2-2.amzn2.0.11.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/libverto@0.2.5-4.amzn2.0.2?arch=aarch64&upstream=libverto-0.2.5-4.amzn2.0.2.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/libxml2@2.9.1-6.amzn2.5.13?arch=aarch64&upstream=libxml2-2.9.1-6.amzn2.5.13.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/lua@5.1.4-15.amzn2.0.2?arch=aarch64&upstream=lua-5.1.4-15.amzn2.0.2.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/ncurses@6.0-8.20170212.amzn2.1.8?arch=aarch64&upstream=ncurses-6.0-8.20170212.amzn2.1.8.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/ncurses-base@6.0-8.20170212.amzn2.1.8?arch=noarch&upstream=ncurses-6.0-8.20170212.amzn2.1.8.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/ncurses-libs@6.0-8.20170212.amzn2.1.8?arch=aarch64&upstream=ncurses-6.0-8.20170212.amzn2.1.8.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/nspr@4.35.0-1.amzn2?arch=aarch64&upstream=nspr-4.35.0-1.amzn2.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/nss@3.90.0-2.amzn2.0.2?arch=aarch64&upstream=nss-3.90.0-2.amzn2.0.2.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/nss-pem@1.0.3-5.amzn2?arch=aarch64&upstream=nss-pem-1.0.3-5.amzn2.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/nss-softokn@3.90.0-6.amzn2.0.2?arch=aarch64&upstream=nss-softokn-3.90.0-6.amzn2.0.2.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/nss-softokn-freebl@3.90.0-6.amzn2.0.2?arch=aarch64&upstream=nss-softokn-3.90.0-6.amzn2.0.2.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/nss-sysinit@3.90.0-2.amzn2.0.2?arch=aarch64&upstream=nss-3.90.0-2.amzn2.0.2.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/nss-tools@3.90.0-2.amzn2.0.2?arch=aarch64&upstream=nss-3.90.0-2.amzn2.0.2.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/nss-util@3.90.0-1.amzn2?arch=aarch64&upstream=nss-util-3.90.0-1.amzn2.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/openldap@2.4.44-25.amzn2.0.7?arch=aarch64&upstream=openldap-2.4.44-25.amzn2.0.7.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/openssl-libs@1.0.2k-24.amzn2.0.13?arch=aarch64&epoch=1&upstream=openssl-1.0.2k-24.amzn2.0.13.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/p11-kit@0.23.22-1.amzn2.0.1?arch=aarch64&upstream=p11-kit-0.23.22-1.amzn2.0.1.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/p11-kit-trust@0.23.22-1.amzn2.0.1?arch=aarch64&upstream=p11-kit-0.23.22-1.amzn2.0.1.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/pcre@8.32-17.amzn2.0.3?arch=aarch64&upstream=pcre-8.32-17.amzn2.0.3.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/pinentry@0.8.1-17.amzn2.0.2?arch=aarch64&upstream=pinentry-0.8.1-17.amzn2.0.2.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/popt@1.13-16.amzn2.0.2?arch=aarch64&upstream=popt-1.13-16.amzn2.0.2.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/pth@2.0.7-23.amzn2.0.2?arch=aarch64&upstream=pth-2.0.7-23.amzn2.0.2.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/publicsuffix-list-dafsa@20240208-1.amzn2.0.1?arch=noarch&upstream=publicsuffix-list-20240208-1.amzn2.0.1.src.rpm&distro=amzn-2"
"pkg:pypi/pycurl@7.19.0"
"pkg:pypi/pygpgme@0.3"
"pkg:rpm/amzn/pygpgme@0.3-9.amzn2.0.3?arch=aarch64&upstream=pygpgme-0.3-9.amzn2.0.3.src.rpm&distro=amzn-2"
"pkg:pypi/pyliblzma@0.5.3"
"pkg:rpm/amzn/pyliblzma@0.5.3-25.amzn2?arch=aarch64&upstream=pyliblzma-0.5.3-25.amzn2.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/python@2.7.18-1.amzn2.0.8?arch=aarch64&upstream=python-2.7.18-1.amzn2.0.8.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/python-iniparse@0.4-9.amzn2?arch=noarch&upstream=python-iniparse-0.4-9.amzn2.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/python-libs@2.7.18-1.amzn2.0.8?arch=aarch64&upstream=python-2.7.18-1.amzn2.0.8.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/python-pycurl@7.19.0-19.amzn2.0.2?arch=aarch64&upstream=python-pycurl-7.19.0-19.amzn2.0.2.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/python-urlgrabber@3.10-9.amzn2.0.1?arch=noarch&upstream=python-urlgrabber-3.10-9.amzn2.0.1.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/python2-rpm@4.11.3-48.amzn2.0.4?arch=aarch64&upstream=rpm-4.11.3-48.amzn2.0.4.src.rpm&distro=amzn-2"
"pkg:pypi/pyxattr@0.5.1"
"pkg:rpm/amzn/pyxattr@0.5.1-5.amzn2.0.2?arch=aarch64&upstream=pyxattr-0.5.1-5.amzn2.0.2.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/readline@6.2-10.amzn2.0.2?arch=aarch64&upstream=readline-6.2-10.amzn2.0.2.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/rpm@4.11.3-48.amzn2.0.4?arch=aarch64&upstream=rpm-4.11.3-48.amzn2.0.4.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/rpm-build-libs@4.11.3-48.amzn2.0.4?arch=aarch64&upstream=rpm-4.11.3-48.amzn2.0.4.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/rpm-libs@4.11.3-48.amzn2.0.4?arch=aarch64&upstream=rpm-4.11.3-48.amzn2.0.4.src.rpm&distro=amzn-2"
"pkg:pypi/rpm-python@4.11.3"
"pkg:rpm/amzn/sed@4.2.2-5.amzn2.0.2?arch=aarch64&upstream=sed-4.2.2-5.amzn2.0.2.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/setup@2.8.71-10.amzn2.0.1?arch=noarch&upstream=setup-2.8.71-10.amzn2.0.1.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/shared-mime-info@1.8-4.amzn2?arch=aarch64&upstream=shared-mime-info-1.8-4.amzn2.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/sqlite@3.7.17-8.amzn2.1.2?arch=aarch64&upstream=sqlite-3.7.17-8.amzn2.1.2.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/system-release@2-16.amzn2?arch=aarch64&epoch=1&upstream=system-release-2-16.amzn2.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/tzdata@2024a-1.amzn2.0.1?arch=noarch&upstream=tzdata-2024a-1.amzn2.0.1.src.rpm&distro=amzn-2"
"pkg:pypi/urlgrabber@3.10"
"pkg:rpm/amzn/vim-data@9.0.2153-1.amzn2.0.1?arch=noarch&epoch=2&upstream=vim-9.0.2153-1.amzn2.0.1.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/vim-minimal@9.0.2153-1.amzn2.0.1?arch=aarch64&epoch=2&upstream=vim-9.0.2153-1.amzn2.0.1.src.rpm&distro=amzn-2"
"pkg:pypi/wsgiref@0.1.2"
"pkg:rpm/amzn/xz-libs@5.2.2-1.amzn2.0.3?arch=aarch64&upstream=xz-5.2.2-1.amzn2.0.3.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/yum@3.4.3-158.amzn2.0.7?arch=noarch&upstream=yum-3.4.3-158.amzn2.0.7.src.rpm&distro=amzn-2"
"pkg:pypi/yum-metadata-parser@1.1.4"
"pkg:rpm/amzn/yum-metadata-parser@1.1.4-10.amzn2.0.2?arch=aarch64&upstream=yum-metadata-parser-1.1.4-10.amzn2.0.2.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/yum-plugin-ovl@1.1.31-46.amzn2.0.1?arch=noarch&upstream=yum-utils-1.1.31-46.amzn2.0.1.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/yum-plugin-priorities@1.1.31-46.amzn2.0.1?arch=noarch&upstream=yum-utils-1.1.31-46.amzn2.0.1.src.rpm&distro=amzn-2"
"pkg:rpm/amzn/zlib@1.2.7-19.amzn2.0.3?arch=aarch64&upstream=zlib-1.2.7-19.amzn2.0.3.src.rpm&distro=amzn-2"
```


## SBOM attestation and verification using Kyverno policy

To sign attestations, install Cosign and generate a public-private key pair.

```
cosign generate-key-pair
```
This will generate the `cosign.key` and `cosign.pub` files in the current directory.

To sign attestations, use the cosign attest command. This command will sign your attestations and publish them to the OCI registry.

```
# ${IMAGE} is REPOSITORY/PATH/NAME:TAG
cosign attest --key cosign.key --predicate <file> --type <predicate type>  ${IMAGE} 

```

The following cosign command creates the in-toto format attestation and signs it with the specified credentials using the custom predicate type https://syft.org/BOM/v1:

```
cosign attest ghcr.io/nirmata/demo-java-sbom:ubuntujre7 --key cosign.key --predicate demo-java-sbom/sboms/ubuntujre7.json --type https://syft.org/BOM/v1
```

The policy below verifies the package urls of the sbom and blocks pods if any of the package urls match oracle.

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: attest-sbom
spec:
  validationFailureAction: Enforce
  background: false
  webhookTimeoutSeconds: 30
  failurePolicy: Fail
  rules:
    - name: attest
      match:
        any:
        - resources:
            kinds:
              - Pod
      verifyImages:
      - imageReferences:
        - "ghcr.io/nirmata*"
        attestations:
          - type: https://syft.org/BOM/v1
            attestors:
            - entries:
              - keys:
                  publicKeys: |-
                    -----BEGIN PUBLIC KEY-----
                    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEBgIImyAQSO4AI36uPF0FOj133HPJ
                    COAbRQly2B64JDYc+OLhJPhJM8H2BNU5LFAh64Bt79QWKyKaH1vNZRGxUw==
                    -----END PUBLIC KEY-----
            conditions:
              - all:
                - key: "{{ regex_match('^.*oracle.*$', '{{ artifacts[].purl }}') }}"
                  operator: Equals
                  value: false
```

Verify the package URL for the images. 

```
cat openjdk11.json | jq ".artifacts[].purl" | grep -i oracle
"pkg:generic/oracle/openjdk@11.0.16"
```

```
cat correto17.json | jq ".artifacts[].purl" | grep -i oracle
```


To verify the policy, deploy the policy and try to run two different images. The `openjdk11` image has `Oracle` in the package urls and will be blocked by the policy. 

```
kubectl run openjdk11-testpod --image=ghcr.io/nirmata/demo-java-sbom:openjdk11
Error from server: admission webhook "mutate.kyverno.svc-fail" denied the request:

resource Pod/default/openjdk11-testpod was blocked due to the following policies

attest-sbom:
  attest: '.attestations[0].attestors[0].entries[0].keys: attestation checks failed
    for ghcr.io/nirmata/demo-java-sbom:openjdk11 and predicate https://syft.org/BOM/v1: '
```

Try running the `correto17` image and it will go through as it does not contain `Oracle` in the package urls. 

```
kubectl run correto17-testpod --image=ghcr.io/nirmata/demo-java-sbom:correto17
pod/correto17-testpod created
```

## Building

Build images:

```sh
make build
```

Push images:
```sh
make push
```

Generate SBOMs:
```sh
make sbom
```

