#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let url = "postgresql://neondb_owner:npg_C2zyAux9UkJL@ep-curly-smoke-aqo0tbrb-pooler.c-8.us-east-1.aws.neon.tech/neondb?sslmode=require";

    println!("Conectando (30s timeout)...");
    match sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(30))
        .connect(url)
        .await
    {
        Err(e) => println!("✗ {e:#}"),
        Ok(pool) => {
            println!("✓ Conexión OK");
            match sqlx::query("SELECT version()").fetch_one(&pool).await {
                Ok(row) => {
                    let v: String = sqlx::Row::try_get(&row, 0).unwrap_or_default();
                    println!("  server: {v}");
                }
                Err(e) => println!("✗ query: {e}"),
            }
            print!("Migraciones... ");
            match sqlx::migrate!("./migrations").run(&pool).await {
                Ok(_)  => println!("✓ OK"),
                Err(e) => println!("✗ {e:#}"),
            }
        }
    }
    Ok(())
}
