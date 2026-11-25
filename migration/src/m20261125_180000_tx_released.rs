//! Add a `tx_released` column to the `batch_transfer` table, set once the signed TX of an outgoing
//! transfer may be held by others.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(BatchTransfer::Table)
                    .add_column(
                        ColumnDef::new(BatchTransfer::TxReleased)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(BatchTransfer::Table)
                    .drop_column(BatchTransfer::TxReleased)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum BatchTransfer {
    Table,
    TxReleased,
}
