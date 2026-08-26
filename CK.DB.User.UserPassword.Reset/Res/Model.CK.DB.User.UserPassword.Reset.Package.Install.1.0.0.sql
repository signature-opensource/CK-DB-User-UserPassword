--[beginscript]

alter table CK.tUserPassword add IsTemporary bit not null
    constraint DF_CK_tUserPassword_IsTemporary default( 0 );

--[endscript]
