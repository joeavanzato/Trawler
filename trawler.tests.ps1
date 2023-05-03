
# Invoke-Pester -CodeCoverage  .\trawler.ps1
# Invoke-Pester

. .\trawler.ps1

BeforeAll {
    $detection = [PSCustomObject]@{
        Name = 'Test Detection'
        Risk = 'Medium'
        Source = 'Test'
        Technique = "T0000: Test"
        Meta = "Test"
    }
    $low_detection = [PSCustomObject]@{
        Name = 'Test Detection'
        Risk = 'Low'
        Source = 'Test'
        Technique = "T0000: Test"
        Meta = "Test"
    }
    $high_detection = [PSCustomObject]@{
        Name = 'Test Detection'
        Risk = 'High'
        Source = 'Test'
        Technique = "T0000: Test"
        Meta = "Test"
    }
    mock Export-CSV
    mock Write-Host
    $outpath = ".\detection_test.csv"
}



Describe "Write-Detection" {
    BeforeEach {
        $detection_list = New-Object -TypeName "System.Collections.ArrayList"
    }
    Context "Console not suppressed" {
        BeforeAll {
            $hide_console_output = $false
        }
        It "Writes two lines to console" {
            Write-Detection $detection
            Should -Invoke -CommandName Write-Host -Times 2 -Exactly
        }
    }
    Context "Console suppressed" {
        BeforeAll {
            $hide_console_output = $true
        }
        It "Writes zero lines to console" {
            Write-Detection $detection
            Should -Invoke -CommandName Write-Host -Times 0 -Exactly
        }
    }
    Context "Output File is Writable" {
        BeforeAll {
            $output_writable = $true
        }
        It "Should output to file" {
            Write-Detection $detection
            Should -Invoke -CommandName Export-CSV -Times 1 -Exactly
        }
    }
    Context "Output File is not Writable" {
        BeforeAll {
            $output_writable = $false
        }
        It "Should not output to file" {
            Write-Detection $detection
            Should -Invoke -CommandName Export-CSV -Times 0 -Exactly
        }
    }
    Context "Detection Added to List" {
        It "Should add one detection to detection_list" {
            Write-Detection $detection
            $detection_list.Count | Should -Be 1
        }
    }
}

Describe "Detection-Metrics" {
    BeforeEach {
        $detection_list = New-Object -TypeName "System.Collections.ArrayList"
        mock Export-CSV
        $outpath = ".\detection_test.csv"
        $output_writable = $true
    }
    Context "General Detection Metrics" {
        It "Writes 7 lines to console" {
            Detection-Metrics
            Should -Invoke -CommandName Write-Host -Times 7 -Exactly
        }
    }
    Context "General Detection Metrics" {
        It "Adds 2 detections and counts them" {
            Write-Detection $low_detection
            Detection-Metrics
            Should -Invoke -CommandName Export-CSV -Times 1 -Exactly
            $detection_list.Count | Should -Be 1
        }
    }
}

Describe "Write-Message" {
    BeforeEach {
        mock Write-Host
    }
    Context "Write Message" {
        It "Writes 1 line to console" {
            Write-Message
            Should -Invoke -CommandName Write-Host -Times 1 -Exactly
        }
    }

}
