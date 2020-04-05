import subprocess

def vdf_execute(vdf_input_integer, vdf_difficulty):
    # Call command line vdf-cli in Rust.
    vdf_output = ''
    cmd = ["vdf-cli", hex(vdf_input_integer)[2:], str(vdf_difficulty)]
    print (cmd)
    res = subprocess.check_output(cmd)
    for line in res.splitlines():
        # process the output line by line
        vdf_output = line
        break

    if len(vdf_output) == 0:
        raise Exception('vdf_execute() NOT EXECUTED PROPERLY!')
    #vdf_output = vdf_output[:516]
    print (vdf_output)
    return int('0x'+vdf_output.decode("utf-8") , 0)


def vdf_verify(vdf_input_integer, vdf_difficulty, vdf_output_integer):
    # Call command line vdf-cli in Rust.
    vdf_output = ''
    cmd = ["vdf-cli", hex(vdf_input_integer)[2:], str(vdf_difficulty), '00' + hex(vdf_output_integer)[2:]]
    print (cmd)
    res = subprocess.check_output(cmd)
    for line in res.splitlines():
        # process the output line by line
        vdf_output = line
        break

    if len(vdf_output) == 0:
        raise Exception('vdf_verify() NOT EXECUTED PROPERLY!')
    print (vdf_output)
    return vdf_output.decode("utf-8").strip() == 'Proof is valid'



output = vdf_execute(int('0xaaaaaaaaaa',0), 1000)
print (output)
print (vdf_verify(int('0xaaaaaaaaaa',0), 1000, output))
