rule NestedLayer
{
    strings:
        $layer = "NESTEDLAYER:"
    condition:
        $layer
}

rule AlienStruct
{
    strings:
        $alien = "ALIENSTRUCT:"
    condition:
        $alien
}

rule CircularPayload
{
    strings:
        $loop = "CIRCULARPAYLOAD:"
    condition:
        $loop
}

rule DepthPayload
{
    strings:
        $bomb = "DEPTHPAYLOAD:"
    condition:
        $bomb
}

rule FaultyPayload
{
    strings:
        $fault_marker = "FAULTYPAYLOAD:"
        $fault_payload = "B64PAYLOAD:"
    condition:
        any of them
}
