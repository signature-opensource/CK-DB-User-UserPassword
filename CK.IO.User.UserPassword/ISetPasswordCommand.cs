using CK.Auth;
using CK.Cris;

namespace CK.IO.User.UserPassword;

/// <summary>
/// Changes the password of an existing password user.
/// The actor must be the target user itself (ActorId must match UserId).
/// Maps to <c>UserPasswordTable.SetPasswordAsync</c> which operates in <c>UCLMode.UpdateOnly</c>.
/// <para>
/// The user changes its own password: this requires the <see cref="ICommandAuthCritical">Critical</see> level (a recent
/// login), so that a session or a calling party at Normal level cannot take over the account.
/// </para>
/// </summary>
public interface ISetPasswordCommand : ICommand<ICrisBasicCommandResult>, ICommandCurrentCulture, ICommandAuthCritical
{
    /// <summary>
    /// Gets or sets the target user identifier. Must match the authenticated <c>ActorId</c>.
    /// </summary>
    public int UserId { get; set; }

    /// <summary>
    /// Gets or sets the new password to set.
    /// </summary>
    public string Password { get; set; }
}
