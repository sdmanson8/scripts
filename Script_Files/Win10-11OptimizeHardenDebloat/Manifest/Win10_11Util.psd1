# PowerShell module manifest for the Win10_11Util loader module.
@{
    RootModule            = '..\Module\Win10_11Util.psm1'
    ModuleVersion         = '2.0.2'
    Author                = 'sdmanson8'
    Description           = 'Module for Windows fine-tuning and automating the routine tasks'
    CompatiblePSEditions  = @('Core', 'Desktop')
    ProcessorArchitecture = 'None'
    FunctionsToExport     = '*'
}
