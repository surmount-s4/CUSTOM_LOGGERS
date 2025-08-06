## Cmd Line

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

cmd
Copy
Edit
gpupdate /force
