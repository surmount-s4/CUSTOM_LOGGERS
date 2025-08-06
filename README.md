## Cmd Line

#### Prereq: 
Windows enterprise and working group policy editor

#### Steps:
Step 1: Enable "Audit Process Creation" via Group Policy
Open Group Policy Editor:

Press Win + R, type gpedit.msc, and press Enter.

Navigate to:

Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > System Audit Policies > Detailed Tracking
Double-click Audit Process Creation:

Check Success (and optionally Failure).

Click OK.

Step 2: Enable Command-Line Logging (for full command-line capture)
This allows Event ID 4688 to include the command-line arguments (i.e., what was typed in cmd, PowerShell, etc.)

Still in Group Policy, navigate to:

Computer Configuration > Administrative Templates > System > Audit Process Creation
Enable: Include command line in process creation events

Set to Enabled

Click OK

📌 This setting populates the "CommandLine" field in Event 4688.

Step 3: Force Group Policy Update (Optional)
You can wait for the Group Policy to apply or force it:

gpupdate /force



## Powershell 

#### Prereq: 
Windows enterprise and working group policy editor

#### Steps:

Step 1. Enable PowerShell Logging via Group Policy
a. Script Block Logging
Logs actual code that runs, even if obfuscated or loaded from memory.

Path:
Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell

Setting:
Turn on PowerShell Script Block Logging → Enabled
Optionally check “Log script block invocation start/stop events.”

Results in Event ID 4104 in:

Applications and Services Logs >
    Microsoft >
        Windows >
            PowerShell >
                Operational
b. Module Logging
Logs commands run by PowerShell modules.

Setting:
Turn on Module Logging → Enabled

In Module Names click on "Show"
Here add two lines for matching:

Microsoft.PowerShell.*
Microsoft.WSMan.Management

Step 2: Force Group Policy Update (Optional)
You can wait for the Group Policy to apply or force it:

gpupdate /force

