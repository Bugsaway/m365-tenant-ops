@{
    ExcludeRules = @(
        'PSUseShouldProcessForStateChangingFunctions',   # Offboarding declares SupportsShouldProcess at script level, steps go through ShouldProcess
        'PSAvoidUsingEmptyCatchBlock',
        'PSAvoidUsingPlainTextForPassword',              # Password is generated in memory, never a parameter
        'PSAvoidUsingConvertToSecureStringWithPlainText'
    )
    Rules = @{ PSUseCompatibleSyntax = @{ Enable = $true; TargetVersions = @('5.1', '7.0') } }
}
