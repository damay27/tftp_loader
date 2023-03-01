define connect
    target remote localhost:3333
end

define reload
    directory
    file build/tftp_loader.elf
    load
    monitor reset init
end

define reset
    monitor reset init
end

define rerun
    reset
    continue
end
