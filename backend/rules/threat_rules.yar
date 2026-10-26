/* rules/threat_signatures.yar */

rule Suspicious_Reflection_Exec {
    meta:
        description = "Detects dynamic execution, reflection, and DEX class loading"
        severity = "HIGH"
    strings:
        // Handles variable whitespace in bytecode descriptors
        $exec = /Runtime\s*;\s*->\s*exec/ ascii wide
        $refl = "java/lang/reflect/Method" ascii wide
        $dex_load = "dalvik/system/DexClassLoader" ascii wide
        $path_load = "dalvik/system/PathClassLoader" ascii wide
    condition:
        $exec or ($refl and ($dex_load or $path_load))
}

rule Native_Command_Execution {
    meta:
        description = "Detects shell command execution inside native C/C++ libraries (.so)"
        severity = "CRITICAL"
    strings:
        $system = "system" ascii fullword
        $popen = "popen" ascii fullword
        $sh = "/system/bin/sh" ascii wide
    condition:
        $sh or ($system and $popen)
}

rule SMS_Intercept_Pattern {
    meta:
        description = "Detects SMS handling methods and broadcast suppression"
        severity = "HIGH"
    strings:
        $sms_mgr = "android/telephony/SmsManager" ascii wide
        $send_msg = "sendTextMessage" ascii wide
        $abort = "abortBroadcast" ascii wide
    condition:
        ($sms_mgr and $send_msg) or $abort
}