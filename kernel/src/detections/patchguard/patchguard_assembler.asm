.code
    _trigger_patchguard_bugcheck proc
        int 20h
        ret
    _trigger_patchguard_bugcheck endp
END