#!/bin/bash

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

# VARS

initramfs_location=/boot
initramfs_name=initrd.img-6.1.0-10-amd64
zst_output_arch_name=root_fs_archive
block_size=13976
tmp_file_sys_name=tmp_rootfs
root_file_sys_name=rootfs

unpack_Func() {

    if ! test -f "$initramfs_location/$initramfs_name"; then
        echo "Cannot find: $initramfs_location/$initramfs_name"
        echo "Check location and try again."
        echo "Exiting ..."
        exit
    fi

    echo "Copying $initramfs_location/$initramfs_name to working directory(current)"
    cp $initramfs_location/$initramfs_name .
    echo "Extracting $initramfs_name..."
    dd if=$initramfs_name skip=$block_size of=$zst_output_arch_name.zst
    zstd -d $zst_output_arch_name.zst
    rm $zst_output_arch_name.zst
    mkdir $tmp_file_sys_name
    mv $zst_output_arch_name $tmp_file_sys_name
    cpio -ivF $tmp_file_sys_name/$zst_output_arch_name -D $tmp_file_sys_name
    rm $tmp_file_sys_name/$zst_output_arch_name
    echo "Complete!"
    echo "Output (1) file: $tmp_file_sys_name"
}

pack_Func() {

    if [ ! -d "$tmp_file_sys_name" ]; then
        echo "$tmp_file_sys_name does not exist. Maybe it was given a different name?"
        echo "Exiting ..."
        exit
    fi

    echo "Zipping $tmp_file_sys_name back into $initramfs_name..."
    find $tmp_file_sys_name/ -printf "%P\n" | cpio -o -H newc -R root:root -D $tmp_file_sys_name | zstd -10 > $root_file_sys_name
    rm -R $tmp_file_sys_name
    chown root:root $root_file_sys_name
    cpio -ivF $initramfs_name
    rm $initramfs_name
    find kernel/ | cpio -o -H newc -R root:root > $initramfs_name
    rm -R kernel/
    chown root:root $initramfs_name
    cat $root_file_sys_name >> $initramfs_name
    rm $root_file_sys_name
    echo "Complete!"
    echo "Output (1) file: $initramfs_name"

    while true; do
        echo "!WARNING! UPDATING EXISTING INITRAMFS IF LOCATED IN BOOT SECTOR WILL BREAK SYSTEM IF BAD IMAGE SUPPLIED PLEASE ENSURE SYSTEM IS BACKED UP BEFORE UPDATING"
        read -p 'Update existing initramfs? y/N: ' input
        case $input in
            [yY]*)
                echo 'Updating ...'

                if ! test -f "$initramfs_location/$initramfs_name"; then
                    echo "Cannot find: $initramfs_location/$initramfs_name"
                    echo "Check location and try again."
                    exit
               fi
                rm $initramfs_location/$initramfs_name
                cp $initramfs_name $initramfs_location
                break
                ;;
            [nN]*)
                echo 'Exiting ...'
                exit
                break
                ;;
            *)
                echo 'Invalid input' >&2
        esac
    done

}

while true; do
    read -p 'Unpack or pack initramfs? u/P: ' input
    case $input in
        [uU]*)
            unpack_Func
            break
            ;;
        [pP]*)
            pack_Func
            break
            ;;
         *)
            echo 'Invalid input' >&2
    esac
done

exit
