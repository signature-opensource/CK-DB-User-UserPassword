using CK.Core;
using CK.Cris;
using CK.DB.Auth;
using CK.IO.User.UserPassword;
using CK.SqlServer;
using System;
using System.Threading.Tasks;

namespace CK.DB.User.UserPassword;

public partial class Package
{
    [CommandHandler]
    public virtual async Task<ICrisBasicCommandResult> HandleSetPasswordCommandAsync( ISqlCallContext ctx, UserMessageCollector collector, ISetPasswordCommand cmd, UserPasswordTable table )
    {
        using( ctx.Monitor.OpenInfo( $"Handling ISetPasswordCommand. (ActorId: {cmd.ActorId})" ) )
        {
            var res = cmd.CreateResult();
            try
            {
                await table.SetPasswordAsync( ctx, cmd.ActorId.GetValueOrDefault(), cmd.UserId, cmd.Password );
                ctx.Monitor.Info( $"User's password has successfully been set. (ActorId: {cmd.ActorId}, UserId: {cmd.UserId})" );
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

    [CommandHandler]
    public virtual async Task<ICrisBasicCommandResult> HandleCreateOrUpdatePasswordAsync( ISqlCallContext ctx, UserMessageCollector collector, ICreateOrUpdatePasswordCommand cmd, UserPasswordTable table )
    {
        using( ctx.Monitor.OpenInfo( $"Handling ICreateOrUpdatePasswordCommand. (ActorId: {cmd.ActorId})" ) )
        {
            var res = cmd.CreateResult();
            try
            {
                var uclMode = ResolveUCLMode( cmd );
                var uclResult = await table.CreateOrUpdatePasswordUserAsync( ctx, cmd.ActorId.GetValueOrDefault(), cmd.UserId, cmd.Password, uclMode );
                if( uclMode == UCLMode.CreateOnly && uclResult.OperationResult != UCResult.Created )
                {
                    ctx.Monitor.Error( $"User's password has not been created. (ActorId: {cmd.ActorId}, UserId: {cmd.UserId})" );
                    collector.Error( $"User's password has not been created. (ActorId: {cmd.ActorId}, UserId: {cmd.UserId})", "User.PasswordCreationFailed" );
                }
                if( uclMode == UCLMode.UpdateOnly && uclResult.OperationResult != UCResult.Updated )
                {
                    ctx.Monitor.Error( $"User's password has not been updated. (ActorId: {cmd.ActorId}, UserId: {cmd.UserId})" );
                    collector.Error( $"User's password has not been updated. (ActorId: {cmd.ActorId}, UserId: {cmd.UserId})", "User.PasswordUpdateFailed" );
                }
                if( uclMode == UCLMode.CreateOrUpdate && uclResult.OperationResult != UCResult.Updated && uclResult.OperationResult != UCResult.Created )
                {
                    ctx.Monitor.Error( $"User's password has not been created nor updated. (ActorId: {cmd.ActorId}, UserId: {cmd.UserId})" );
                    collector.Error( $"User's password has not been created nor updated. (ActorId: {cmd.ActorId}, UserId: {cmd.UserId})", "User.PasswordCreateOrUpdateFailed" );
                }

                if( collector.ErrorCount == 0 )
                {
                    collector.Info( $"User's password has successfully been created or updated. (ActorId: {cmd.ActorId}, UserId: {cmd.UserId})", "User.PasswordCreatedOrUpdated" );
                }
            }
            catch( SqlDetailedException ex ) when( ex.InnerSqlException is not null )
            {
                ctx.Monitor.Error( $"Error while handling ICreateOrUpdatePasswordCommand: {ex.Message}", ex );
                collector.Error( ex );
            }
            catch( Exception e )
            {
                ctx.Monitor.Error( e );
                collector.Error( "An error occurred while creating or updating user's password.", "User.PasswordCreateOrUpdateFailed" );
            }
            res.SetUserMessages( collector );
            return res;
        }
    }

    /// <summary>
    /// The current user adds a password (create only).
    /// </summary>
    /// <param name="ctx">The call context to use.</param>
    /// <param name="collector">The message collector.</param>
    /// <param name="cmd">The command.</param>
    /// <param name="table">The password table.</param>
    /// <returns>The result.</returns>
    [CommandHandler]
    public virtual async Task<ICrisBasicCommandResult> HandleAddPasswordAsync( ISqlCallContext ctx, UserMessageCollector collector, IAddPasswordCommand cmd, UserPasswordTable table )
    {
        var res = cmd.CreateResult();
        var actorId = cmd.ActorId.GetValueOrDefault();
        try
        {
            var r = await table.CreateOrUpdatePasswordUserAsync( ctx, actorId, actorId, cmd.Password, UCLMode.CreateOnly );
            if( r.OperationResult == UCResult.Created )
            {
                ctx.Monitor.Info( ActivityMonitor.Tags.SecurityCritical, $"User #{actorId} added a password." );
                collector.Info( "The password has been added.", "User.PasswordAdded" );
            }
            else
            {
                collector.Error( "You already have a password: change it instead.", "User.PasswordExists" );
            }
        }
        catch( Exception ex )
        {
            ctx.Monitor.Error( $"Error while adding the password of user #{actorId}.", ex );
            collector.Error( "An error occurred while adding the password.", "User.PasswordAddFailed" );
        }
        res.SetUserMessages( collector );
        return res;
    }

    /// <summary>
    /// The current user removes its password. The user's last way to log in is never removed.
    /// </summary>
    /// <param name="ctx">The call context to use.</param>
    /// <param name="collector">The message collector.</param>
    /// <param name="cmd">The command.</param>
    /// <param name="table">The password table.</param>
    /// <returns>The result.</returns>
    [CommandHandler]
    public virtual async Task<ICrisBasicCommandResult> HandleRemovePasswordAsync( ISqlCallContext ctx, UserMessageCollector collector, IRemovePasswordCommand cmd, UserPasswordTable table )
    {
        var res = cmd.CreateResult();
        var actorId = cmd.ActorId.GetValueOrDefault();
        try
        {
            switch( await table.RemovePasswordAsync( ctx, actorId ) )
            {
                case PasswordRemoveResult.Removed:
                    ctx.Monitor.Info( ActivityMonitor.Tags.SecurityCritical, $"User #{actorId} removed its password." );
                    collector.Info( "The password has been removed.", "User.PasswordRemoved" );
                    break;
                case PasswordRemoveResult.LastLoginMethod:
                    collector.Error( "Your password is your last way to log in: it cannot be removed.", "User.PasswordLastLoginMethod" );
                    break;
                default:
                    collector.Error( "You have no password.", "User.NoPassword" );
                    break;
            }
        }
        catch( Exception ex )
        {
            ctx.Monitor.Error( $"Error while removing the password of user #{actorId}.", ex );
            collector.Error( "An error occurred while removing the password.", "User.PasswordRemoveFailed" );
        }
        res.SetUserMessages( collector );
        return res;
    }

    UCLMode ResolveUCLMode( ICreateOrUpdatePasswordCommand cmd )
    {
        UCLMode mode = cmd.CreationMode switch
        {
            CreationMode.CreateOnly => UCLMode.CreateOnly,
            CreationMode.UpdateOnly => UCLMode.UpdateOnly,
            CreationMode.CreateOrUpdate => UCLMode.CreateOrUpdate,
            _ => throw new ArgumentOutOfRangeException( nameof( cmd.CreationMode ) )
        };

        if( cmd.WithCheckLogin ) mode |= UCLMode.WithCheckLogin;
        if( cmd.WithActualLogin ) mode |= UCLMode.WithActualLogin;

        return mode;
    }
}
