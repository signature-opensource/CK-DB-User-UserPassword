using CK.Core;
using CK.Cris;
using CK.DB.Auth;
using CK.IO.User.UserPassword;
using CK.SqlServer;
using CK.Testing;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System;
using System.Linq;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.DB.User.UserPassword.Tests;

[TestFixture]
public class UserPasswordCrisTests
{
#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider adding the 'required' modifier or declaring as nullable.
    AsyncServiceScope _scope;
    IServiceProvider _services;
    CrisExecutionContext _executor;
    RawCrisReceiver _crisReceiver;
    PocoDirectory _pocoDir;
    Package _package;
    UserPasswordTable _table;
#pragma warning restore CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider adding the 'required' modifier or declaring as nullable.

    [OneTimeSetUp]
    public void OneTimeSetUp()
    {
        _scope = SharedEngine.AutomaticServices.CreateAsyncScope();
        _services = _scope.ServiceProvider;

        _pocoDir = _services.GetRequiredService<PocoDirectory>();
        _executor = _services.GetRequiredService<CrisExecutionContext>();
        _crisReceiver = _services.GetRequiredService<RawCrisReceiver>();
        
        _package = _services.GetRequiredService<Package>();
        _table = _services.GetRequiredService<UserPasswordTable>();
    }

    [OneTimeTearDown]
    public async Task OneTimeTearDownAsync()
    {
        await _scope.DisposeAsync();
    }

    [Test]
    public async Task can_create_or_update_password_Async()
    {
        var userId = 1;
        var pwd = "success";
        var cmd = _pocoDir.Create<ICreateOrUpdatePasswordCommand>( cmd =>
        {
            cmd.ActorId = 1;
            cmd.UserId = userId;
            cmd.Password = pwd;
            cmd.CreationMode = CreationMode.CreateOrUpdate;
        } );
        var executingCmd = await _executor.ExecuteRootCommandAsync( cmd );
        var res = executingCmd.WithResult<ICrisBasicCommandResult>().Result;
        res.ShouldNotBeNull();
        res.Success.ShouldBeTrue();
        res.UserMessages.ShouldNotBeEmpty();
        TestHelper.Monitor.Info( string.Join( "\r\n", res.UserMessages.Select( um => um.Message ) ) );
        using( var ctx = new SqlStandardCallContext() )
        {
            var loginRes = await _table.LoginUserAsync( ctx, 1, pwd, actualLogin: false );
            loginRes.IsSuccess.ShouldBeTrue( "Login should succeed with the created password." );
        }
    }

    [Test]
    public async Task can_set_password_Async()
    {
        var userId = 1;
        var pwd = "test";
        var cmd = _pocoDir.Create<ISetPasswordCommand>( cmd =>
        {
            cmd.ActorId = 1;
            cmd.UserId = userId;
            cmd.Password = pwd;
        } );
        var executingCmd = await _executor.ExecuteRootCommandAsync( cmd );

        var res = executingCmd.WithResult<ICrisBasicCommandResult>().Result;
        res.ShouldNotBeNull();
        res.Success.ShouldBeTrue();
        res.UserMessages.ShouldNotBeEmpty();
        TestHelper.Monitor.Info( string.Join( "\r\n", res.UserMessages.Select( um => um.Message ) ) );
        using( var ctx = new SqlStandardCallContext() )
        {
            var loginRes = await _table.LoginUserAsync( ctx, 1, "success", actualLogin: false );
            loginRes.IsSuccess.ShouldBeFalse( "Login should fail with the another password." );
            loginRes = await _table.LoginUserAsync( ctx, 1, pwd, actualLogin: false );
            loginRes.IsSuccess.ShouldBeTrue( "Login should succeed with the created password." );
        }
    }

    [Test]
    public async Task a_user_adds_a_password_and_cannot_remove_its_last_login_method_Async()
    {
        var user = _services.GetRequiredService<Actor.UserTable>();
        int userId;
        using( var ctx = new SqlStandardCallContext() )
        {
            userId = await user.CreateUserAsync( ctx, 1, Guid.NewGuid().ToString() );
        }
        // Each command in its own scope: the UserMessageCollector is scoped (the errors of a command must not leak).
        async Task<ICrisBasicCommandResult> ExecuteAsync( ICrisBasicCommandResult? _, IAbstractCommand cmd )
        {
            await using var scope = SharedEngine.AutomaticServices.CreateAsyncScope();
            var executor = scope.ServiceProvider.GetRequiredService<CrisExecutionContext>();
            return (await executor.ExecuteRootCommandAsync( cmd )).WithResult<ICrisBasicCommandResult>().Result.ShouldNotBeNull();
        }

        // No password: nothing to remove.
        var r = await ExecuteAsync( null, _pocoDir.Create<IRemovePasswordCommand>( c => { c.ActorId = userId; c.ActualActorId = userId; } ) );
        r.Success.ShouldBeFalse();
        r.UserMessages.ShouldContain( m => m.ResName == "User.NoPassword" );

        // Added (create only): the user logs in with it.
        r = await ExecuteAsync( null, _pocoDir.Create<IAddPasswordCommand>( c => { c.ActorId = userId; c.ActualActorId = userId; c.Password = "first"; } ) );
        r.Success.ShouldBeTrue();
        using( var ctx = new SqlStandardCallContext() )
        {
            (await _table.LoginUserAsync( ctx, userId, "first", actualLogin: false )).IsSuccess.ShouldBeTrue();
        }
        // Added again: refused (ISetPasswordCommand changes it).
        r = await ExecuteAsync( null, _pocoDir.Create<IAddPasswordCommand>( c => { c.ActorId = userId; c.ActualActorId = userId; c.Password = "second"; } ) );
        r.Success.ShouldBeFalse();
        r.UserMessages.ShouldContain( m => m.ResName == "User.PasswordExists" );

        // The password is the user's only way to log in: it is not removed.
        r = await ExecuteAsync( null, _pocoDir.Create<IRemovePasswordCommand>( c => { c.ActorId = userId; c.ActualActorId = userId; } ) );
        r.Success.ShouldBeFalse();
        r.UserMessages.ShouldContain( m => m.ResName == "User.PasswordLastLoginMethod" );
        using( var ctx = new SqlStandardCallContext() )
        {
            (await _table.LoginUserAsync( ctx, userId, "first", actualLogin: false )).IsSuccess.ShouldBeTrue();
            await user.DestroyUserAsync( ctx, 1, userId );
        }
    }

    // The following methods test IncomingValidators.
    // They cannot be tested with the CrisExecutionContext.
    // This one use the RawCrisReceiver. The CK.DB.User.UserPassword SUT project has no
    // dependency on CK.Cris.Executor (where RawCrisReceiver is).
    [Test]
    public async Task cannot_use_empty_password_Async()
    {
        var userId = 1;
        var setCmd = _pocoDir.Create<ISetPasswordCommand>( cmd =>
        {
            cmd.ActorId = 1;
            cmd.UserId = userId;
            cmd.Password = string.Empty;
        } );
        var validationResult = await _crisReceiver.IncomingValidateAsync( TestHelper.Monitor, _services, setCmd );
        validationResult.Success.ShouldBeFalse( "Setting an empty password should fail." );
        validationResult.ValidationMessages.Any( vm => vm.Level == UserMessageLevel.Error ).ShouldBeTrue( "There must be at least one Error message." );

        var createCmd = _pocoDir.Create<ICreateOrUpdatePasswordCommand>( cmd =>
        {
            cmd.ActorId = 1;
            cmd.UserId = userId;
            cmd.Password = string.Empty;
        } );
        validationResult = await _crisReceiver.IncomingValidateAsync( TestHelper.Monitor, _services, createCmd );
        validationResult.Success.ShouldBeFalse( "Creating with an empty password should fail." );
        validationResult.ValidationMessages.Any( vm => vm.Level == UserMessageLevel.Error ).ShouldBeTrue( "There must be at least one Error message." );
    }

    [Test]
    public async Task only_user_can_set_its_own_password_Async()
    {
        var userId = 3712;
        var cmd = _pocoDir.Create<ISetPasswordCommand>( cmd =>
        {
            cmd.ActorId = 1;
            cmd.UserId = userId;
            cmd.Password = "even if it is a strong pwd $µ*5464+=/-3'é-(('";
        } );
        var validationResult = await _crisReceiver.IncomingValidateAsync( TestHelper.Monitor, _services, cmd );
        validationResult.Success.ShouldBeFalse( "Setting a password for another user should fail." );
        validationResult.ValidationMessages.Any( vm => vm.Level == UserMessageLevel.Error ).ShouldBeTrue( "There must be at least one Error message." );
    }
}
