use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // SQLite supports a single option per ALTER TABLE statement
        manager
            .alter_table(
                Table::alter()
                    .table(BatchTransfer::Table)
                    .add_column(
                        ColumnDef::new(BatchTransfer::ApplyWhenFinal)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(BatchTransfer::Table)
                    .add_column(ColumnDef::new(BatchTransfer::ConflictHeight).big_integer())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(BatchTransfer::Table)
                    .drop_column(BatchTransfer::ConflictHeight)
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(BatchTransfer::Table)
                    .drop_column(BatchTransfer::ApplyWhenFinal)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum BatchTransfer {
    Table,
    ApplyWhenFinal,
    ConflictHeight,
}
