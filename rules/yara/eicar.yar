// EICAR anti-malware test file: a harmless, industry-standard test pattern
// used to verify that file scanning works end to end (SPEC §16).
rule EICAR_Test_File
{
    meta:
        description = "EICAR anti-malware test file (harmless test pattern)"
        reference = "https://www.eicar.org/download-anti-malware-testfile/"
        severity = "test"

    strings:
        $marker = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!"

    condition:
        $marker and filesize < 256
}
