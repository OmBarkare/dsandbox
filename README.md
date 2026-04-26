# dsandbox (deceptive sandbox)
a sandbox environment to run binaries, without actually executing the syscalls but making
the binary think it executed them succesfully

I got this idea from HackByte's (hackathon) theme "patch the reality". We are patching the
reality for the binary

## Features
- can look at what syscall is going to be executed
- change and look at register values
- read at write to child's memory

## What I want it to do
I want to be able to run binaries using dsandbox and log all of its behaviour without letting the binary
actually execute suspicious syscalls, also without letting the binary know that it is being traced.

I would like to like it in a format so that it is easier to analyse. I want to add different levels of verbosity for logging.

Also add functionality to let the user control what action to take when specific syscalls are encountered
(eg. if to replace the write buffer of child process, and what to replace it with)