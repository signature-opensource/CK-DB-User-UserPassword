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
                var uclResult = await table.CreateOrUpdatePasswordUserAsync( ctx, cmd.ActorId.GetValueOrDefault(), cmd.UserId, cmd.Password, cmd.UCLMode );
                if( cmd.UCLMode == UCLMode.CreateOnly && uclResult.OperationResult != UCResult.Created )
                {
                    ctx.Monitor.Error( $"User's password has not been created. (ActorId: {cmd.ActorId}, UserId: {cmd.UserId})" );
                    collector.Error( $"User's password has not been created. (ActorId: {cmd.ActorId}, UserId: {cmd.UserId})", "User.PasswordCreationFailed" );
                }
                if( cmd.UCLMode == UCLMode.UpdateOnly && uclResult.OperationResult != UCResult.Updated )
                {
                    ctx.Monitor.Error( $"User's password has not been updated. (ActorId: {cmd.ActorId}, UserId: {cmd.UserId})" );
                    collector.Error( $"User's password has not been updated. (ActorId: {cmd.ActorId}, UserId: {cmd.UserId})", "User.PasswordUpdateFailed" );
                }
                if( cmd.UCLMode == UCLMode.CreateOrUpdate && uclResult.OperationResult != UCResult.Updated && uclResult.OperationResult != UCResult.Created )
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
}
