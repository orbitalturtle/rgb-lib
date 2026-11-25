//! Add the `silent_payment_output` table, holding the received silent payment (BIP352) outputs with
//! the tweak needed to spend them.

use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(SilentPaymentOutput::Table)
                    .if_not_exists()
                    .col(pk_auto(SilentPaymentOutput::Idx))
                    .col(string_uniq(SilentPaymentOutput::Outpoint))
                    .col(blob(SilentPaymentOutput::Tweak))
                    .col(integer(SilentPaymentOutput::BatchTransferIdx))
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(SilentPaymentOutput::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum SilentPaymentOutput {
    Table,
    Idx,
    Outpoint,
    Tweak,
    BatchTransferIdx,
}
