namespace CK.IO.User.UserPassword.Reset;

/// <summary>
/// Extends <see cref="UserPassword.ISetPasswordCommand"/> with the ability to flag the
/// new password as a temporary one.
/// </summary>
public interface ISetPasswordCommand : UserPassword.ISetPasswordCommand
{
    /// <summary>
    /// Gets or sets whether the password being set is a temporary one.
    /// Defaults to false: setting a password clears any previous temporary state.
    /// </summary>
    public bool IsTemporary { get; set; }
}
