/* rules/threat_signatures.yar */

rule Suspicious_Reflection_Exec {
    meta:
        description = "Detects usage of reflection and command execution APIs"
        severity = "HIGH"
    strings:
        $exec = "Runtime.getRuntime().exec" ascii
        $refl = "java/lang/reflect/Method" ascii
        $load_class = "dalvik/system/DexClassLoader" ascii
    condition:
        $exec or ($refl and $load_class)
}

rule SMS_Intercept_Pattern {
    meta:
        description = "Detects SMS sending and interception methods"
        severity = "CRITICAL"
    strings:
        $sms1 = "android.telephony.SmsManager" ascii
        $sms2 = "sendTextMessage" ascii
        $abort = "abortBroadcast" ascii
    condition:
        all of ($sms*) or $abort
}