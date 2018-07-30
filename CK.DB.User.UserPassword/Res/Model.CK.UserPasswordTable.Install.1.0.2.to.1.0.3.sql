
alter table CK.tUserPassword add 
    FailedAttemptCount tinyint not null constraint DF_CK_UserPassword default(0);
