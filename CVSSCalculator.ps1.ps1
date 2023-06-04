# Define the function to calculate CVSS score
function CalculateCVSS {
    param(
        [Parameter(Mandatory = $true, HelpMessage = "How is the file accessed? Enter L for local, A for adjacent network, or N for remote network.")]
        [ValidateSet("L", "A", "N")]
        [string]$AttackVector,

        [Parameter(Mandatory = $true, HelpMessage = "How complex is it to exploit the vulnerability in the file? Enter H for high, L for low, or N for none.")]
        [ValidateSet("H", "L", "N")]
        [string]$AttackComplexity,

        [Parameter(Mandatory = $true, HelpMessage = "What level of privileges does an attacker need to exploit the vulnerability in the file? Enter N for none, L for low, or H for high.")]
        [ValidateSet("N", "L", "H")]
        [string]$PrivilegesRequired,

        [Parameter(Mandatory = $true, HelpMessage = "Does an attacker require user interaction to exploit the vulnerability in the file? Enter R for required or N for not required.")]
        [ValidateSet("R", "N")]
        [string]$UserInteraction,

        [Parameter(Mandatory = $true, HelpMessage = "Does the vulnerability in the file affect only the user or can it impact a broader system? Enter U for user or C for system.")]
        [ValidateSet("U", "C")]
        [string]$Scope,

        [Parameter(Mandatory = $true, HelpMessage = "What is the impact on the confidentiality of user information if the vulnerability in the file is exploited? Enter N for none, L for low, H for high, or X if not defined.")]
        [ValidateSet("N", "L", "H", "X")]
        [string]$ConfidentialityImpact,

        [Parameter(Mandatory = $true, HelpMessage = "What is the impact on the integrity of user information if the vulnerability in the file is exploited? Enter N for none, L for low, H for high, or X if not defined.")]
        [ValidateSet("N", "L", "H", "X")]
        [string]$IntegrityImpact,

        [Parameter(Mandatory = $true, HelpMessage = "What is the impact on the availability of user information or the system if the vulnerability in the file is exploited? Enter N for none, L for low, H for high, or X if not defined.")]
        [ValidateSet("N", "L", "H", "X")]
        [string]$AvailabilityImpact,

        [Parameter(Mandatory = $true, HelpMessage = "How important is confidentiality to the affected system? Enter L for low, M for medium, H for high, or X if not defined.")]
        [ValidateSet("L", "M", "H", "X")]
        [string]$ConfidentialityRequirement,

        [Parameter(Mandatory = $true, HelpMessage = "How important is integrity to the affected system? Enter L for low, M for medium, H for high, or X if not defined.")]
        [ValidateSet("L", "M", "H", "X")]
        [string]$IntegrityRequirement,

        [Parameter(Mandatory = $true, HelpMessage = "How important is availability to the affected system? Enter L for low, M for medium, H for high, or X if not defined.")]
        [ValidateSet("L", "M", "H", "X")]
        [string]$AvailabilityRequirement
    )

    # Calculate the Base Score
    $AV = switch ($AttackVector) {
        "L" { 0.395 }
        "A" { 0.646 }
        "N" { 1.0 }
    }

    $AC = switch ($AttackComplexity) {
        "H" { 0.35 }
        "L" { 0.61 }
        "N" { 0.71 }
    }

    $PR = switch ($PrivilegesRequired) {
        "N" { 0.85 }
        "L" { 0.62 }
        "H" { 0.27 }
    }

    $UI = switch ($UserInteraction) {
        "R" { 0.85 }
        "N" { 0.62 }
    }

    $S = switch ($Scope) {
        "U" { 0.0 }
        "C" { 1.0 }
    }

    $impactValues = @()
    $impactValues += switch ($ConfidentialityImpact) {
        "N" { 0.0 }
        "L" { 0.22 }
        "H" { 0.56 }
        "X" { $null }
    }
    $impactValues += switch ($IntegrityImpact) {
        "N" { 0.0 }
        "L" { 0.22 }
        "H" { 0.56 }
        "X" { $null }
    }
    $impactValues += switch ($AvailabilityImpact) {
        "N" { 0.0 }
        "L" { 0.22 }
        "H" { 0.56 }
        "X" { $null }
    }

    $impact = $impactValues | Measure-Object -Average | Select-Object -ExpandProperty Average

    $baseScore = [math]::min((($impact + (1 - $S)) * ($AC * $AV * $PR)), 10)

    # Calculate the Temporal Score
    $temporalScore = $baseScore

    # Calculate the Environmental Score
    $CR = switch ($ConfidentialityRequirement) {
        "L" { 0.5 }
        "M" { 1.0 }
        "H" { 1.51 }
        "X" { $null }
    }

    $IR = switch ($IntegrityRequirement) {
        "L" { 0.5 }
        "M" { 1.0 }
        "H" { 1.51 }
        "X" { $null }
    }

    $AR = switch ($AvailabilityRequirement) {
        "L" { 0.5 }
        "M" { 1.0 }
        "H" { 1.51 }
        "X" { $null }
    }

    $environmentalScore = [math]::min((($impact + (1 - $S)) * ($AC * $AV * $PR) * ($CR * $IR * $AR)), 10)

    # Display the CVSS scores
    Write-Host "CVSS Base Score: $baseScore"
    Write-Host "CVSS Temporal Score: $temporalScore"
    Write-Host "CVSS Environmental Score: $environmentalScore"
}

# Prompt for input and calculate CVSS scores for each file
$filesCount = Read-Host "Enter the number of files you want to calculate CVSS scores for:"

for ($i = 1; $i -le $filesCount; $i++) {
    Write-Host "File $i"
    $AttackVector = Read-Host "How is the file accessed? (L: local, A: adjacent network, N: remote network)"
    $AttackComplexity = Read-Host "How complex is it to exploit the vulnerability? (H: high, L: low, N: none)"
    $PrivilegesRequired = Read-Host "What level of privileges is required to exploit the vulnerability? (N: none, L: low, H: high)"
    $UserInteraction = Read-Host "Does an attacker require user interaction to exploit the vulnerability? (R: required, N: not required)"
    $Scope = Read-Host "Does the vulnerability affect only the user or can it impact a broader system? (U: user, C: system)"
    $ConfidentialityImpact = Read-Host "What is the impact on confidentiality if the vulnerability is exploited? (N: none, L: low, H: high, X: not defined)"
    $IntegrityImpact = Read-Host "What is the impact on integrity if the vulnerability is exploited? (N: none, L: low, H: high, X: not defined)"
    $AvailabilityImpact = Read-Host "What is the impact on availability if the vulnerability is exploited? (N: none, L: low, H: high, X: not defined)"
    $ConfidentialityRequirement = Read-Host "How important is confidentiality to the affected system? (L: low, M: medium, H: high, X: not defined)"
    $IntegrityRequirement = Read-Host "How important is integrity to the affected system? (L: low, M: medium, H: high, X: not defined)"
    $AvailabilityRequirement = Read-Host "How important is availability to the affected system? (L: low, M: medium, H: high, X: not defined)"

    CalculateCVSS -AttackVector $AttackVector -AttackComplexity $AttackComplexity `
        -PrivilegesRequired $PrivilegesRequired -UserInteraction $UserInteraction `
        -Scope $Scope -ConfidentialityImpact $ConfidentialityImpact `
        -IntegrityImpact $IntegrityImpact -AvailabilityImpact $AvailabilityImpact `
        -ConfidentialityRequirement $ConfidentialityRequirement `
        -IntegrityRequirement $IntegrityRequirement `
        -AvailabilityRequirement $AvailabilityRequirement

    Write-Host
}
