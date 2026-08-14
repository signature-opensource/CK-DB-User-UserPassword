using CK.Core;
using CK.Cris;
using CK.SqlServer;
using System;
using System.Threading.Tasks;

namespace CK.DB.User.UserPassword.Reset;

/// <summary>
/// Supersedes <c>CK.DB.User.UserPassword.Package.HandleSetPasswordCommandAsync</c> so that the
/// <see cref="IO.User.UserPassword.Reset.ISetPasswordCommand.IsTemporary"/> flag brought by this
/// package is honored.
/// <para>
/// Declaring <see cref="ICommandHandler{T}"/> makes the Cris engine elect this service over any
/// other <c>[CommandHandler]</c> for the same command.
/// </para>
/// </summary>
public class SetPasswordCommandHandler : IAutoService,
                                         ICommandHandler<IO.User.UserPassword.ISetPasswordCommand>
{
    [CommandHandler]
    public virtual async Task<ICrisBasicCommandResult> SetPasswordAsync( ISqlCallContext ctx,
                                                                         UserMessageCollector collector,
                                                                         IO.User.UserPassword.Reset.ISetPasswordCommand cmd,
                                                                         UserPasswordResetTable table )
    {
        using( ctx.Monitor.OpenInfo( $"Handling ISetPasswordCommand. (ActorId: {cmd.ActorId}, IsTemporary: {cmd.IsTemporary})" ) )
        {
            var res = cmd.CreateResult();
            try
            {
                await table.SetPasswordAsync( ctx, cmd.ActorId.GetValueOrDefault(), cmd.UserId, cmd.Password, cmd.IsTemporary );
                ctx.Monitor.Info( $"User's password has successfully been set. (ActorId: {cmd.ActorId}, UserId: {cmd.UserId}, IsTemporary: {cmd.IsTemporary})" );
                collector.Info( $"User's password has successfully been set. (ActorId: {cmd.ActorId}, UserId: {cmd.UserId})", "User.PasswordSet" );
            }
            catch( SqlDetailedException ex ) when( ex.InnerSqlException is not null )
            {
                ctx.Monitor.Error( $"Error while handling ISetPasswordCommand: {ex.Message}", ex );
                collector.Error( ex );
            }
            catch( Exception e )
            {
                ctx.Monitor.Error( e );
                collector.Error( "An error occurred while setting user's password.", "User.PasswordSetFailed" );
            }

            res.SetUserMessages( collector );
            return res;
        }
    }
}
