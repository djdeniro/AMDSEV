#!/bin/bash

. ./stable-commits

BUILD_DIR=`pwd`/src
OUTPUT_DIR=`pwd`/output
NUM_OF_CORES=`grep -c ^processor /proc/cpuinfo`

run_cmd()
{
	echo "$*"

	$*
	if [ $? -ne 0 ]; then
		echo "ERROR: $*"
		exit 1
	fi
}

fetch_kernel()
{
	echo "Fetching $1"
	if [ "$1" = "kvm" ]; then
		KERNEL_COMMIT=${KVM_KERNEL_COMMIT}
		KERNEL_GIT_URL=${KVM_GIT_URL}
	elif [ "$1" = "tip" ]; then
		KERNEL_COMMIT=${TIP_KERNEL_COMMIT}
		KERNEL_GIT_URL=${TIP_GIT_URL}
	else
		echo "** ERROR **"
		exit 1
	fi

	run_cmd "mkdir -p ${BUILD_DIR}/$1"
	run_cmd "git clone --single-branch -b ${KERNEL_COMMIT} ${KERNEL_GIT_URL} ${BUILD_DIR}/$1"
}

build_kernel()
{
	if [ ! -d $BUILD_DIR/$1 ]; then
		fetch_kernel "$1"
	fi
	cd $BUILD_DIR/$1
	cp /boot/config-$(uname -r) .config
	sed  -ie s/CONFIG_LOCALVERSION.*/CONFIG_LOCALVERSION=\"\"/g .config
	./scripts/config --enable CONFIG_AMD_MEM_ENCRYPT
	./scripts/config --enable CONFIG_AMD_KVM_SEV
	./scripts/config --disable CONFIG_DEBUG_INFO
	./scripts/config --module CRYPTO_DEV_CCP_DD
	./scripts/config --disable CONFIG_LOCALVERSION_AUTO
	yes "" | make olddefconfig
	run_cmd "make -j `getconf _NPROCESSORS_ONLN` deb-pkg LOCALVERSION=-$1"
	run_cmd "mkdir -p $OUTPUT_DIR/$1"
	run_cmd "mv ../linux-*${1}*.deb $OUTPUT_DIR/$1"
}

fetch_ovmf()
{
	run_cmd "mkdir -p ${BUILD_DIR}/edk2"
	run_cmd "git clone ${EDK2_GIT_URL} ${BUILD_DIR}/edk2"
	cd ${BUILD_DIR}/edk2
}

build_ovmf()
{
	if [ ! -d $BUILD_DIR/edk2 ]; then
		fetch_ovmf
	fi
	cd $BUILD_DIR/edk2
	run_cmd "make -C BaseTools"
	. ./edksetup.sh
	run_cmd "nice build --cmd-len=64436 \
		-DDEBUG_ON_SERIAL_PORT=TRUE \
		-n $(getconf _NPROCESSORS_ONLN) \
		-a X64 \
		-a IA32 \
		-t GCC5 \
	        -p OvmfPkg/OvmfPkgIa32X64.dsc"
	run_cmd "mkdir -p $OUTPUT_DIR/qemu-output/share/qemu"
	run_cmd "cp Build/Ovmf3264/DEBUG_GCC5/FV/OVMF_CODE.fd $OUTPUT_DIR/qemu-output/share/qemu"
	run_cmd "cp Build/Ovmf3264/DEBUG_GCC5/FV/OVMF_VARS.fd $OUTPUT_DIR/qemu-output/"
}

fetch_qemu()
{
	run_cmd "mkdir -p ${BUILD_DIR}/qemu"
	run_cmd "git clone --single-branch -b ${QEMU_COMMIT} ${QEMU_GIT_URL} ${BUILD_DIR}/qemu"
	cd ${BUILD_DIR}/qemu
}

build_qemu()
{
	if [ ! -d $BUILD_DIR/qemu ]; then
		fetch_qemu
	fi
	cd $BUILD_DIR/qemu
	run_cmd "./configure --target-list=x86_64-softmmu --enable-trace-backend=log\
		--prefix=$OUTPUT_DIR/qemu-output"
	run_cmd "make -j$(getconf _NPROCESSORS_ONLN)"
	run_cmd "make -j$(getconf _NPROCESSORS_ONLN) install"
	run_cmd "cp $BUILD_DIR/../launch-qemu.sh $OUTPUT_DIR/qemu-output"
}

dep_install ()
{
	# install the build dependencies 
	run_cmd "sudo apt-get -y install git build-essential zlib1g-dev libglib2.0-dev libpixman-1-dev uuid-dev nasm bison acpica-tools libncurses5-dev libssl-dev fakeroot dpkg-dev bc libelf-dev"
}

dep_install
build_kernel "kvm"
build_qemu
build_ovmf
