bios.sh:
chroot . mount -t sysfs sysfs /sys/
chroot . mount -t proc proc /proc/
chroot . mount -t devtmpfs udev /dev/
chroot . mount -t devpts devpts /dev/pts/
chroot . mount -t tmpfs tmpfs /run/
chroot . mount -t tmpfs tmpfs /dev/shm/
chroot . mount -t mqueue mqueue /dev/mqueue/
chroot . mount -t hugetlbfs hugetlbfs /dev/hugepages/
chroot . mount -t tmpfs tmpfs /tmp/

grub-install --target=i386-pc /dev/loop0 --root-directory=$PWD
chroot . grub-mkconfig -o /boot/grub/grub.cfg

umount {tmp,dev/{hugepages,mqueue,shm},run,dev/{pts,},proc,sys}/

chroot . passwd -d root


uefi.sh:
chroot . mount -t sysfs sysfs /sys/
chroot . mount -t proc proc /proc/
chroot . mount -t devtmpfs udev /dev/
chroot . mount -t devpts devpts /dev/pts/
chroot . mount -t tmpfs tmpfs /run/
chroot . mount -t tmpfs tmpfs /dev/shm/
chroot . mount -t mqueue mqueue /dev/mqueue/
chroot . mount -t hugetlbfs hugetlbfs /dev/hugepages/
chroot . mount -t tmpfs tmpfs /tmp/

mkdir -m 0700 boot/efi
mount /dev/loop0p1 boot/efi/
grub-install --target=x86_64-efi /dev/loop0p1 --root-directory=$PWD
chroot . grub-mkconfig -o /boot/grub/grub.cfg
mkdir -m 0755 boot/efi/EFI/BOOT
cp -p boot/efi/EFI/debian/grubx64.efi boot/efi/EFI/BOOT/
cp -p boot/efi/EFI/debian/shimx64.efi boot/efi/EFI/BOOT/BOOTX64.EFI
umount boot/efi/

umount {tmp,dev/{hugepages,mqueue,shm},run,dev/{pts,},proc,sys}/

chroot . passwd -d root


both.sh:
chroot . mount -t sysfs sysfs /sys/
chroot . mount -t proc proc /proc/
chroot . mount -t devtmpfs udev /dev/
chroot . mount -t devpts devpts /dev/pts/
chroot . mount -t tmpfs tmpfs /run/
chroot . mount -t tmpfs tmpfs /dev/shm/
chroot . mount -t mqueue mqueue /dev/mqueue/
chroot . mount -t hugetlbfs hugetlbfs /dev/hugepages/
chroot . mount -t tmpfs tmpfs /tmp/

mkdir -m 0700 boot/efi
mount /dev/loop0p2 boot/efi
grub-install --target=x86_64-efi /dev/loop0 --root-directory=$PWD
grub-install --target=i386-pc /dev/loop0 --root-directory=$PWD
chroot . grub-mkconfig -o /boot/grub/grub.cfg
mkdir -m 0755 boot/efi/EFI/BOOT
cp -p boot/efi/EFI/debian/grubx64.efi boot/efi/EFI/BOOT/
cp -p boot/efi/EFI/debian/shimx64.efi boot/efi/EFI/BOOT/BOOTX64.EFI
umount boot/efi/

umount {tmp,dev/{hugepages,mqueue,shm},run,dev/{pts,},proc,sys,boot/efi}/

chroot . passwd -d root
