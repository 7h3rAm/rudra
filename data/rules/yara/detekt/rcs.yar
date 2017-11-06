rule RCS_Scout
{
    meta:
        detection = "Hacking Team RCS Scout"

    strings:
        $filter1 = "$engine5"
        $filter2 = "$start4"
        $filter3 = "$upd2"
        $filter4 = "$lookma6"

        $engine1 = /(E)ngine started/ wide ascii
        $engine2 = /(R)unning in background/ wide ascii
        $engine3 = /(L)ocking doors/ wide ascii
        $engine4 = /(R)otors engaged/ wide ascii
        $engine5 = /(I)\'m going to start it/ wide ascii

        $start1 = /Starting upgrade\!/ wide ascii
        $start2 = /(I)\'m going to start the program/ wide ascii
        $start3 = /(i)s it ok\?/ wide ascii
        $start4 = /(C)lick to start the program/ wide ascii

        $upd1 = /(U)pdJob/ wide ascii
        $upd2 = /(U)pdTimer/ wide ascii

        $lookma1 = /(O)wning PCI bus/ wide
        $lookma2 = /(F)ormatting bios/ wide
        $lookma3 = /(P)lease insert a disk in drive A:/ wide
        $lookma4 = /(U)pdating CPU microcode/ wide
        $lookma5 = /(N)ot sure what's happening/ wide
        $lookma6 = /(L)ook ma, no thread id\! \\\\o\// wide        

    condition:
        (all of ($engine*) or all of ($start*) or all of ($upd*) or 4 of ($lookma*)) and not any of ($filter*)
}

rule RCS_Backdoor
{
    meta:
        detection = "Hacking Team RCS Backdoor"

    strings:
        $filter1 = "$debug3"
        $filter2 = "$log2"
        $filter3 = "error2"

        $debug1 = /\- (C)hecking components/ wide ascii
        $debug2 = /\- (A)ctivating hiding system/ wide ascii
        $debug3 = /(f)ully operational/ wide ascii

        $log1 = /\- Browser activity \(FF\)/ wide ascii
        $log2 = /\- Browser activity \(IE\)/ wide ascii
        
        // Cause false positives.
        //$log3 = /\- About to call init routine at %p/ wide ascii
        //$log4 = /\- Calling init routine at %p/ wide ascii

        $error1 = /\[Unable to deploy\]/ wide ascii
        $error2 = /\[The system is already monitored\]/ wide ascii

    condition:
        (2 of ($debug*) or 2 of ($log*) or all of ($error*)) and not any of ($filter*)
}

rule RCS_Backdoor_New
{
    meta:
        detection = "Hacking Team RCS Backdoor"

    strings:
        $filter1 = "$phone1"
        $filter2 = "$mod1"
        $filter3 = "$conv1"
        $filter4 = "$system1"

        $wallet1  = /(%)APPDATA%\\Feathercoin\\wallet\.dat/ wide ascii
        $wallet1  = /(%)APPDATA%\\Namecoin\\wallet\.dat/ wide ascii
        $wallet1  = /(%)APPDATA%\\Litecoin\\wallet\.dat/ wide ascii
        $wallet1  = /(%)APPDATA%\\Bitcoin\\wallet\.dat/ wide ascii

        $mod1 = /\[Crisis\]\: Network activity restarted/ wide ascii
        $mod2 = /\[Crisis\]\: Network activity inhibited/ wide ascii
        $mod3 = /\[Core Module\]\: Started/ wide ascii
        $mod4 = /\[Inf. Module\]\: Spread to VMWare/ wide ascii
        $mod5 = /\[Inf. Module\]\: Spread to USB Drive/ wide ascii

        $conv1 = /(E)nd of conversation - Start of conversation/ wide ascii
        $conv2 = /(F)ine conversazione - Inizio conversazione/ wide ascii

        $system1 = /(P)rocessor\: %d x %s/ wide ascii
        $system2 = /(M)emory\: / wide ascii
        $system3 = /(D)isk\: / wide ascii
        $system4 = /(B)attery\: %s%d%%/ wide ascii
        $system5 = /(O)S Version\: %s%s%s%s%s/ wide ascii
        $system6 = /(R)egistered to\: %s%s%s%s \{%s\}/ wide ascii
        $system7 = /(L)ocale settings\: %s_%s (UTC %\+\.2d\:%\.2d)/ wide ascii
        $system8 = /(T)ime delta\: %s/ wide ascii
        $system9 = /(U)ser\: %s%s%s%s%s/ wide ascii

    condition:
        (any of ($wallet*) and 3 of ($mod*) and all of ($conv*) and 5 of ($system*))
        and not any of ($filter*)
}
