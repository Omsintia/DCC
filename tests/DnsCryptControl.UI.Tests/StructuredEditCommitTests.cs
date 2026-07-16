using DnsCryptControl.Core.Schema;
using DnsCryptControl.UI.ViewModels;
using DnsCryptControl.UI.Views;

namespace DnsCryptControl.UI.Tests;

/// <summary>
/// F1: the pure commit-decision logic behind the structured pane's editors. The view's
/// code-behind commits an editor's content on focus loss — but LostFocus fires on EVERY
/// focus traversal, so committing unconditionally would mark the editor dirty (and
/// mutate the document) just by tabbing through it. These functions decide whether a
/// control's current content is a REAL edit and produce the typed value
/// <c>ConfigurationViewModel.ApplyEdit</c> expects. Pure POCO logic (no WPF types) —
/// the event wiring itself is compile-verified view plumbing per the plan's
/// TDD-honesty rule.
/// </summary>
public class StructuredEditCommitTests
{
    private static SettingEntryViewModel Entry(SettingValueType type, object? currentValue = null)
    {
        var descriptor = new SettingDescriptor(
            "test_key", string.Empty, type, "n/a", "test doc", "General");
        var entry = new SettingEntryViewModel(descriptor) { Value = currentValue };
        return entry;
    }

    // ------------------------------------------------------------------- Bool

    [Fact]
    public void bool_toggle_on_an_unset_entry_commits_the_new_value()
    {
        var entry = Entry(SettingValueType.Bool);

        Assert.True(StructuredEditCommit.TryPrepareBool(entry, newValue: true, out var value));
        Assert.Equal(true, value);
    }

    [Fact]
    public void bool_echo_of_the_current_value_is_not_a_commit()
    {
        var entry = Entry(SettingValueType.Bool, currentValue: true);

        Assert.False(StructuredEditCommit.TryPrepareBool(entry, newValue: true, out _));
    }

    [Fact]
    public void bool_flip_of_the_current_value_commits()
    {
        var entry = Entry(SettingValueType.Bool, currentValue: true);

        Assert.True(StructuredEditCommit.TryPrepareBool(entry, newValue: false, out var value));
        Assert.Equal(false, value);
    }

    // ------------------------------------------------------------------- Text

    [Fact]
    public void empty_text_on_an_unset_entry_never_creates_the_key()
    {
        // Tabbing through an empty TextBox of an absent key must not write `key = ""`.
        var entry = Entry(SettingValueType.String);

        Assert.False(StructuredEditCommit.TryPrepareText(entry, string.Empty, out _));
    }

    [Fact]
    public void new_text_on_an_unset_entry_commits()
    {
        var entry = Entry(SettingValueType.String);

        Assert.True(StructuredEditCommit.TryPrepareText(entry, "quad9", out var value));
        Assert.Equal("quad9", value);
    }

    [Fact]
    public void unchanged_text_is_not_a_commit()
    {
        var entry = Entry(SettingValueType.String, currentValue: "quad9");

        Assert.False(StructuredEditCommit.TryPrepareText(entry, "quad9", out _));
    }

    [Fact]
    public void changed_text_commits()
    {
        var entry = Entry(SettingValueType.String, currentValue: "quad9");

        Assert.True(StructuredEditCommit.TryPrepareText(entry, "cloudflare", out var value));
        Assert.Equal("cloudflare", value);
    }

    [Fact]
    public void clearing_a_set_text_commits_an_explicit_empty_string()
    {
        var entry = Entry(SettingValueType.String, currentValue: "quad9");

        Assert.True(StructuredEditCommit.TryPrepareText(entry, string.Empty, out var value));
        Assert.Equal(string.Empty, value);
    }

    // ------------------------------------------------------------------- Numbers

    [Fact]
    public void an_empty_number_box_commits_nothing()
    {
        var entry = Entry(SettingValueType.Long, currentValue: 250L);

        Assert.False(StructuredEditCommit.TryPrepareNumber(entry, newValue: null, out _));
    }

    [Fact]
    public void a_long_entry_commits_a_boxed_long()
    {
        var entry = Entry(SettingValueType.Long);

        Assert.True(StructuredEditCommit.TryPrepareNumber(entry, 250d, out var value));
        Assert.Equal(250L, value);
    }

    [Fact]
    public void an_unchanged_long_is_not_a_commit()
    {
        var entry = Entry(SettingValueType.Long, currentValue: 250L);

        Assert.False(StructuredEditCommit.TryPrepareNumber(entry, 250d, out _));
    }

    [Fact]
    public void a_changed_long_commits()
    {
        var entry = Entry(SettingValueType.Long, currentValue: 250L);

        Assert.True(StructuredEditCommit.TryPrepareNumber(entry, 300d, out var value));
        Assert.Equal(300L, value);
    }

    [Theory]
    [InlineData(2.6, 3L)]
    [InlineData(2.5, 3L)] // away-from-zero, not banker's — least surprise for a settings form
    [InlineData(-2.5, -3L)]
    public void a_fractional_value_for_a_long_entry_rounds_away_from_zero(double typed, long expected)
    {
        var entry = Entry(SettingValueType.Long);

        Assert.True(StructuredEditCommit.TryPrepareNumber(entry, typed, out var value));
        Assert.Equal(expected, value);
    }

    [Theory]
    [InlineData(1e19)]
    [InlineData(-1e19)]
    [InlineData(double.NaN)]
    [InlineData(double.PositiveInfinity)]
    public void a_value_unrepresentable_as_long_commits_nothing(double typed)
    {
        var entry = Entry(SettingValueType.Long, currentValue: 250L);

        Assert.False(StructuredEditCommit.TryPrepareNumber(entry, typed, out _));
    }

    [Fact]
    public void a_float_entry_commits_the_double_verbatim()
    {
        var entry = Entry(SettingValueType.Float);

        Assert.True(StructuredEditCommit.TryPrepareNumber(entry, 0.75, out var value));
        Assert.Equal(0.75, value);
    }

    [Fact]
    public void an_unchanged_float_is_not_a_commit()
    {
        // A2's TryGetDouble widens TOML integers, so a Float entry's current value is
        // always a boxed double — an identical re-read must not dirty the editor.
        var entry = Entry(SettingValueType.Float, currentValue: 1.0);

        Assert.False(StructuredEditCommit.TryPrepareNumber(entry, 1.0, out _));
    }

    [Theory]
    [InlineData(double.NaN)]
    [InlineData(double.NegativeInfinity)]
    public void a_non_finite_float_commits_nothing(double typed)
    {
        var entry = Entry(SettingValueType.Float, currentValue: 1.0);

        Assert.False(StructuredEditCommit.TryPrepareNumber(entry, typed, out _));
    }

    [Fact]
    public void a_number_for_a_non_numeric_entry_commits_nothing()
    {
        var entry = Entry(SettingValueType.String, currentValue: "quad9");

        Assert.False(StructuredEditCommit.TryPrepareNumber(entry, 1d, out _));
    }

    // ------------------------------------------------------------------- Lines

    [Fact]
    public void empty_lines_on_an_unset_entry_never_create_the_key()
    {
        var entry = Entry(SettingValueType.StringArray);

        Assert.False(StructuredEditCommit.TryPrepareLines(entry, string.Empty, out _));
    }

    [Fact]
    public void new_lines_on_an_unset_entry_commit_the_parsed_array()
    {
        var entry = Entry(SettingValueType.StringArray);

        Assert.True(StructuredEditCommit.TryPrepareLines(entry, "a\r\nb", out var value));
        Assert.Equal(new[] { "a", "b" }, Assert.IsAssignableFrom<IReadOnlyList<string>>(value));
    }

    [Fact]
    public void lines_equal_to_the_current_array_are_not_a_commit()
    {
        // The display formats with CRLF; a raw LF re-entry of the SAME items (or
        // whitespace-only touch-ups) must not dirty the editor.
        var entry = Entry(SettingValueType.StringArray, currentValue: new[] { "a", "b" });

        Assert.False(StructuredEditCommit.TryPrepareLines(entry, " a \nb\n", out _));
    }

    [Fact]
    public void changed_lines_commit()
    {
        var entry = Entry(SettingValueType.StringArray, currentValue: new[] { "a", "b" });

        Assert.True(StructuredEditCommit.TryPrepareLines(entry, "a", out var value));
        Assert.Equal(new[] { "a" }, Assert.IsAssignableFrom<IReadOnlyList<string>>(value));
    }

    [Fact]
    public void clearing_a_set_array_commits_an_explicit_empty_array()
    {
        var entry = Entry(SettingValueType.StringArray, currentValue: new[] { "a" });

        Assert.True(StructuredEditCommit.TryPrepareLines(entry, string.Empty, out var value));
        Assert.Empty(Assert.IsAssignableFrom<IReadOnlyList<string>>(value));
    }

    [Fact]
    public void an_already_empty_set_array_left_empty_is_not_a_commit()
    {
        var entry = Entry(SettingValueType.StringArray, currentValue: Array.Empty<string>());

        Assert.False(StructuredEditCommit.TryPrepareLines(entry, string.Empty, out _));
    }

    // ------------------------------------------------------------------- Guards

    [Fact]
    public void every_prepare_null_guards_its_entry_and_text()
    {
        var entry = Entry(SettingValueType.String);

        Assert.Throws<ArgumentNullException>(() => StructuredEditCommit.TryPrepareBool(null!, true, out _));
        Assert.Throws<ArgumentNullException>(() => StructuredEditCommit.TryPrepareText(null!, "x", out _));
        Assert.Throws<ArgumentNullException>(() => StructuredEditCommit.TryPrepareText(entry, null!, out _));
        Assert.Throws<ArgumentNullException>(() => StructuredEditCommit.TryPrepareNumber(null!, 1d, out _));
        Assert.Throws<ArgumentNullException>(() => StructuredEditCommit.TryPrepareLines(null!, "x", out _));
        Assert.Throws<ArgumentNullException>(() => StructuredEditCommit.TryPrepareLines(entry, null!, out _));
    }
}
