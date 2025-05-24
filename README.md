# PADLOCK+ – ecosistema p-ádico fractal

> Criptografía pos-cuántica compacta (`mod 5ʳ`), KEM & firma MSIS,
> pensada para pagos al segundo y pruebas auto-auditables.

| ⚙️  Módulo | Estado |
|-----------|--------|
| **padic-core**  | aritmética Mod 5, tests property-based ✅ |
| **padic-crypto**| KEM Compact IND-CCA ✅ · MSIS Compact **constant-time** ✅ |
| **CI**          | `cargo fmt + clippy -D warnings + test + bench` |

---

## ✨ Principales características

* **Todo mod 5** → código mínimo, verificación ultrarrápida.
* **IND-CCA KEM** (Fujisaki–Okamoto) y **MSIS firma** con peso ≤ Ω.
* **Constant-time**: sin ramas secretas, resistente a *timing*.
* Benchmarks en Ryzen 5 3600 (Rust 1.87):

| Operación | Tiempo medio |
|-----------|--------------|
| KeyGen Compact | **≈ 0.58 ms** |
| Sign Compact   | **≈ 1.55 ms** |
| Verify Compact | **≈ 0.77 ms** |

---

## 🚀 Cómo compilar

```bash
# clonar
git clone https://github.com/tu-usuario/padic-core.git
cd padic-core

# compilar todo el workspace
cargo build --release

Ejecutar test:

cargo test --workspace

Benchmarks

cargo bench -p padic-crypto        # requiere Criterion

Estructura repo:

padic-core/            # librería de aritmética
padic-crypto/          # KEM + firma
└─ benches/            # Criterion benches

Roadmap breve
Hito	Fecha estimada
π SIS proofs + p-TSig agregada	2025-Q3
RingCT roll-up	2026-Q2
Mainnet 1 M TPS	2030

🤝 Contribuir
git switch -c feat/nombre-rama

Código formateado (cargo fmt) y sin warnings (cargo clippy -D warnings).

PR a main. Los benches deben compilar con cargo bench --no-run.

Licencia
MIT · consulta el archivo LICENSE.

yaml
Copiar
Editar

Ajusta los textos y las cifras de benchmark según tu CPU si lo deseas.

---

## 3 · Guarda, formatea y añade a Git

```powershell
git add README.md
git commit -m "docs: initial README with features, build, benchmarks"
git push   # ya estás en la rama hardening/msis-ct

