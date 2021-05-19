# pydetours

Single file, 0 compilation, 0 dependancy (other than python), x86/x86_64 hooking in python.

## Examples



### IAT hooking

Lets take the target process `netcat`. Lets say we want to change the port it binds on (this is a contrived example for netcat, but could be useful for other applications).

Target process:

    .\static-binaries\binaries\windows\x86\ncat.exe -4lvvp 5678

Hook script
```python
# support running with embedded python
import os; import sys; sys.path.append(os.path.dirname(__file__))

from pydetours import *
import struct
import socket

@hook_iat(
	'ncat.exe',        # module to hook the import of
	'ws2_32.dll!bind'  # the import: <dll>!<function_name_or_ordinal>
)
def bind_hook(registers):
	sock, addr, namelen = Arguments(registers, 3)        # Parse registers into arguments (autodetect calling convention, and unpack to `bind`s arguments)
	memory[addr + 2:addr + 4] = struct.pack('>H', 7654)  # Replace the `port` in `addr`. Use the `memory` object to get R/W access to the address space (or use ctypes directly)
	# Return nothing/None and the bound function will run (e.g. this case)
	# Return a non-None value (usually an int) and this value will be returned instead of running the bound function

if __name__ == '__main__':
	# Launch the process and inject into it
	launch(
		cmdline=['./static-binaries/binaries/windows/x86/ncat.exe', '-4lvvp', '5678'],
		file_to_inject=__file__,
	)
	# Alternatively inject('ncat.exe', __file__) would inject into a running process
	# Pass `alloc_console=True` to launch/inject if the process is a GUI program and a console is desired
if __name__ == '__hooks__':
	# This code will run inside the injected process upon injection
	print("! I'm running inside the hooked process")
```

Run the script (use 32bit python since the target is 32bit)

    .\python-3.7.9-embed-win32\python.exe .\demo1.py
 
And a console will open for ncat
```
[@] Python stub started
[@] Stub running C:\Users\simon\workspace\pydetours\demo1.py
 * Hooking ncat.exe:ws2_32.dll!bind to run <function bind_hook at 0x02E6B780>
  - Resolved ncat.exe:ws2_32.dll!bind -> thunk=0x00aef82c
  - Created landing at 0x02eb0000
  - Writing function hook landing bytecode to run <function bind_hook at 0x02E6B780> (0x2e6b780)
  - Patching thunk to point to landing
! I'm running inside the hooked process
Ncat: Version 6.47 ( http://nmap.org/ncat )
Ncat: Listening on 0.0.0.0:7654
```

### Instruction hooking

Rather than hooking an import, we can hook an address directly

```python
@hook(
	'gameassembly.dll+0x88B7F0'  # can be <dll>+<offset> or <absolute>
)
def PlayerControl_SetColor(r):
	print('PlayerControl.SetColor', Arguments(r, 2))
	# Similar to `hook_iat`, returning a value will force an immediate return with that value in *ax (i.e. the return value)
	return 1
  
# To work, `hook` replaces the instructions at the provided address with a trampoline.
# By default it detects common function prolouges as relocatable, however if a function does not begin with a recognised prolouge, 
# provide `position_independent_bytes`. pydetours will then relocate exactly that many bytes, and use that space for the trampoline.
# `address:position_independent_bytes` must contain assembly instructions that do not depend on the instruction pointer or contain jumps
@hook('gameassembly.dll+0x887660', position_independent_bytes=10)
def PlayerControl_CoStartMeeting(r):
	print('PlayerControl.CoStartMeeting', Arguments(r, 2))
  
# Note that hooks can be inserted anywhere enough relocatable instructions exist (requires 5 bytes),
# not just at the start of functions (return non-None values with care in this case as the stack may have moved)
```

### Registers

Hooked functions are passed a `Registers` object, representing the registers at the time of hooking. This can be used to read and write the registers.
Modifications to this object will modify the register state on completion of the hook (with the exception of the stack pointer).

```python
@hook('foo.exe+0x112233', position_independent_bytes=7)
def foo_hook(r):
	r.eax += 10
```

#### Arguments

Construct an `Arguments` object from the registers object, and provide the number of arguments.
This will autodetect 32bit or 64bit calling convention and parse the arguments from registers/the stacl.
Modifications to arguments will also be written back.

n.b. floating point arguments are not yet supported.


### Using module introspection

When running inside a hooked process, `pydetours.modules` will be accessible containing the full import and exports of all modules.

Additionally you can inspect the modules of a running foreign process using the same API.

```python
>>> from pydetours import *
>>> from pprint import pprint
>>> 
>>> pid = getpid('ncat.exe')
>>> handle = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
>>> modules = Modules(handle)
>>> pprint(modules)
{'advapi32.dll': Module(name='advapi32.dll', path='C:\\WINDOWS\\System32\\ADVAPI32.dll', <33 imports>, <857 exports>),
# ... snip
 'mswsock.dll': Module(name='mswsock.dll', path='C:\\WINDOWS\\system32\\mswsock.dll', <32 imports>, <63 exports>),
 'ncat.exe': Module(name='ncat.exe', path='C:\\Users\\simon\\workspace\\pydetours\\static-binaries\\binaries\\windows\\x86\\ncat.exe', <5 imports>, <0 exports>),
# ... snip
 'ws2_32.dll': Module(name='ws2_32.dll', path='C:\\WINDOWS\\System32\\WS2_32.dll', <31 imports>, <180 exports>)}
>>>
>>> pprint(modules['ncat.exe'].imports['ws2_32.dll'].by_name)
{'WSACloseEvent': ResolvedFunctionImport(ordinal=45, name='WSACloseEvent', by_ordinal=False, thunk=4716632, original_address=1989827904, resolved_address=1989827904),
# ... snip
 'accept': ResolvedFunctionImport(ordinal=1, name='accept', by_ordinal=False, thunk=4716616, original_address=1989822016, resolved_address=1989822016),
 'bind': ResolvedFunctionImport(ordinal=2, name='bind', by_ordinal=False, thunk=4716588, original_address=1989791120, resolved_address=56164352),
 'closesocket': ResolvedFunctionImport(ordinal=3, name='closesocket', by_ordinal=False, thunk=4716708, original_address=1989792576, resolved_address=1989792576),
 'connect': ResolvedFunctionImport(ordinal=4, name='connect', by_ordinal=False, thunk=4716612, original_address=1989823968, resolved_address=1989823968),
# ... snip
 'socket': ResolvedFunctionImport(ordinal=23, name='socket', by_ordinal=False, thunk=11466808, resolved_address=1989786320)}
 ```
