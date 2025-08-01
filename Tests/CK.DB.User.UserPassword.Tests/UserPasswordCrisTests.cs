using CK.Core;
using CK.Cris;
using CK.DB.Auth;
using CK.IO.User.UserPassword;
using CK.SqlServer;
using CK.Testing;
using Microsoft.Extensions.DependencyInjection;
using NUnit.Framework;
using Shouldly;
using System.Linq;
using System.Threading.Tasks;
using static CK.Testing.MonitorTestHelper;

namespace CK.DB.User.UserPassword.Tests;

[TestFixture]
public class UserPasswordCrisTests
{
#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider adding the 'required' modifier or declaring as nullable.
    AutomaticServices _automaticServices;
    AsyncServiceScope _scope;
    CrisExecutionContext _executor;
    PocoDirectory _pocoDir;
    Package _package;
    UserPasswordTable _table;
#pragma warning restore CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider adding the 'required' modifier or declaring as nullable.

    [OneTimeSetUp]
    public void OneTimeSetUp()
    {
        _scope = SharedEngine.AutomaticServices.CreateAsyncScope();
        var services = _scope.ServiceProvider;

        _pocoDir = services.GetRequiredService<PocoDirectory>();
        _executor = services.GetRequiredService<CrisExecutionContext>();
        _package = services.GetRequiredService<Package>();
        _table = services.GetRequiredService<UserPasswordTable>();
    }

    [OneTimeTearDown]
    public async Task OneTimeTearDownAsync()
    {
        await _scope.DisposeAsync();
        await _automaticServices.DisposeAsync();
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
            cmd.UCLMode = UCLMode.CreateOrUpdate;
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

    // Note: the following methods test IncomingValidators that currently cannot be tested with the CrisExecutionContext.
    //[Test]
    //public async Task cannot_use_empty_password_Async()
    //{
    //    var userId = 1;
    //    var setCmd = _pocoDir.Create<ISetPasswordCommand>( cmd =>
    //    {
    //        cmd.ActorId = 1;
    //        cmd.UserId = userId;
    //        cmd.Password = string.Empty;
    //    } );
    //    var executingSetCmd = _backgroundExecutor.Submit( TestHelper.Monitor, setCmd )
    //                                          .WithResult<ICrisBasicCommandResult>();

    //    var res = await executingSetCmd.ExecutedCommand;
    //    res.ShouldNotBeNull();
    //    res.Result.ShouldBeAssignableTo<ICrisResultError>().ShouldNotBeNull().IsValidationError.ShouldBeTrue();
    //    res.ValidationMessages.Any( vm => vm.Level == UserMessageLevel.Error ).ShouldBeTrue( "Setting an empty password should fail." );

    //    var cmd = _pocoDir.Create<ICreateOrUpdatePasswordCommand>( cmd =>
    //    {
    //        cmd.ActorId = 1;
    //        cmd.UserId = userId;
    //        cmd.Password = string.Empty;
    //    } );
    //    var executingCmd = _backgroundExecutor.Submit( TestHelper.Monitor, cmd )
    //                                          .WithResult<ICrisBasicCommandResult>();

    //    res = await executingCmd.ExecutedCommand;
    //    res.ShouldNotBeNull();
    //    res.Result.ShouldBeAssignableTo<ICrisResultError>().ShouldNotBeNull().IsValidationError.ShouldBeTrue();
    //    res.ValidationMessages.Any( vm => vm.Level == UserMessageLevel.Error ).ShouldBeTrue( "Setting an empty password should fail." );
    //}

    //[Test]
    //public async Task only_user_can_set_its_own_password_Async()
    //{
    //    var userId = 3712;
    //    var cmd = _pocoDir.Create<ISetPasswordCommand>( cmd =>
    //    {
    //        cmd.ActorId = 1;
    //        cmd.UserId = userId;
    //        cmd.Password = "pwd";
    //    } );
    //    var executingCmd = _backgroundExecutor.Submit( TestHelper.Monitor, cmd )
    //                                          .WithResult<ICrisBasicCommandResult>();

    //    var res = await executingCmd.ExecutedCommand;
    //    res.ShouldNotBeNull();
    //    res.Result.ShouldBeAssignableTo<ICrisResultError>().ShouldNotBeNull().IsValidationError.ShouldBeTrue();
    //    res.ValidationMessages.Any( vm => vm.Level == UserMessageLevel.Error ).ShouldBeTrue( "Setting a password for another user should fail." );
    //}
}
