using System.Collections.Generic;
using System.Linq;

namespace DnsCryptControl.Core.Validation;

public enum ValidationSeverity { Error, Warning }

public sealed record ValidationIssue(string KeyPath, string Message, ValidationSeverity Severity);

public sealed class ValidationReport
{
    public ValidationReport(IReadOnlyList<ValidationIssue> issues) => Issues = issues;

    public IReadOnlyList<ValidationIssue> Issues { get; }

    public bool IsValid => !Issues.Any(i => i.Severity == ValidationSeverity.Error);
}
