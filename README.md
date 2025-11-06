# Cryptographic Accumulators for ZK Nullifiers (EVM-oriented)

> **Status:** initial draft (README.md).
> **Scope:** practical, on-chain-verifiable accumulators to implement *nullifiers* in zero-knowledge systems, with an emphasis on Ethereum / EVM.

---

## Why accumulators for nullifiers?

A **nullifier** is a unique tag (typically a field element or hash) published once to prevent double-use of a secret (e.g., spending an anonymous note). On chain we need to enforce:

1. **Uniqueness:** a nullifier $N$ must not have appeared before (non-membership at spend time), then it is added to the *spent* set.
2. **Compact state:** the on-chain state should be constant-size or at least *logarithmic*, so gas stays bounded as the set grows.
3. **Fast verification:** verifiers (contracts) should check membership/non-membership efficiently using precompiles where possible.
4. **Updatability:** appending a new nullifier should be simple; existing witnesses should either remain valid or be updatable cheaply.
5. **Trust & assumptions:** minimal trusted setup; clear cryptographic assumptions; smooth UX for provers.

An **accumulator** is a short commitment to a (growing) set $S$ that supports short proofs of *membership* ($x\in S$) and, in some designs, *non-membership* ($x\notin S$).

---

## Notation

* Let $S \subset \mathcal{U}$ be the current set of nullifiers.
* An **accumulator value** $\mathsf{Acc}(S)$ is a short digest/commitment stored on chain.
* A **witness** for $e\in\mathcal{U}$ is denoted $\mathsf{w}_e$.
* Pairing groups use generator $g\in G_1$, secret $\tau\in\mathbb{F}_p$, bilinear map $e:G_1\times G_2\to G_T$.
* RSA groups use unknown order modulus $N$ and generator $g\in \mathbb{Z}_N^*$.
* Hashes: $\mathsf{H}(\cdot)$; hash-to-prime $\mathsf{Hp}(\cdot)$ when required.

---

## Requirements for the ZK-Nullifier use case

* **Append-only:** once a nullifier is published, it remains in the set.
* **Operations needed**

  * **Non-membership** at spend time: prove $N\notin S_{\text{spent}}$ (or, equivalently, prove $N$ was *not* committed previously).
  * **Membership** at conflict resolution / fraud proofs: show $N\in S$ (e.g., to justify that a duplicate spend is invalid).
* **On-chain footprint**

  * One accumulator word (or a few curve points).
  * Proof sizes: constant or logarithmic.
  * Verification chores aligned with EVM precompiles (BN254 pairings, keccak/Poseidon, modexp).
* **Witness maintenance**

  * Ideally: existing users need not track every update.
  * Practically: if updates are needed, they should be cheap or server-assisted.

---

## Families of accumulators covered

1. **(Sparse) Merkle Trees (SMT)**
2. **Pairing-based (Nguyen/Boneh–Boyen-style)**
3. **KZG-based (polynomial-commitment set accumulators)**
4. **RSA-based (Benaloh–de Mare / Camenisch–Lysyanskaya-style)**

Each chapter details math, witness maintenance, (non)membership, and complexity.

---

## 1. (Sparse) Merkle Trees

### Construction (append-only, key–value set)

For a fixed key domain (e.g., $2^{256}$), define a full binary tree of depth $d$ with default value $\bot$.

* Leaves: at index $i=\mathsf{H}(e)$ store value $v_i$ (e.g., $1$ for “present”).
* Internal nodes: hash of children; root $R$ is on chain.

**Membership proof** for $e$ is the path of sibling hashes from leaf to root:
$$
\pi_e=\{h_0,\dots,h_{d-1}\},\quad \text{size } O(\log |\mathcal{U}|).
$$

**Non-membership** in *sparse* trees uses the canonical $\bot$ leaf: the proof shows the path leads to the default leaf at index $\mathsf{H}(e)$.

### Updates

Append $e$ by setting leaf $i$ from $\bot$ to $1$ and re-hashing along the path: $O(\log |\mathcal{U}|)$ node updates.

### Prover state, witnesses, and maintenance

* **Prover keeps:** either nothing (can query a full node for a proof) or the last proof $\pi_e$.
* **On addition of any new element:** a previously stored $\pi_e$ may become stale; can be *updated* with $O(\log |\mathcal{U}|)$ sibling replacements or simply re-queried.

### (Non)membership & verification

* **Membership:** verify path recomputation ends at $R$.
* **Non-membership (sparse):** verify path ends at default leaf at index $\mathsf{H}(e)$.

### Complexity (asymptotic)

* **Witness size:** $O(\log |\mathcal{U}|)$ hashes.
* **Prover time:** generate/update proof $O(\log |\mathcal{U}|)$.
* **Verifier time/space:** recompute $O(\log |\mathcal{U}|)$ hashes; on chain, gas $\propto$ path length.

### EVM notes

* **Pros:** No trusted setup; easy append; non-membership supported (sparse); gas-predictable (hash loops).
* **Cons:** Proofs/log gas grow with depth; Poseidon (for ZK) vs Keccak (for EVM) trade-offs.

---

## 2. Pairing-based accumulators (Nguyen / Boneh–Boyen style)

These accumulate *linear factors* in the exponent using a secret $s$ at setup.

### Setup

Pick secret $s\in\mathbb{F}_p$; publish $(g, g^s)$ (and often $g^{s^i}$ for bounded universes). Encode each element $e$ as a field element.

### Accumulator and witnesses

Define
$$
\mathsf{Acc}(S)=g^{\prod_{x\in S} (s+x)}.
$$

For $e\in S$, a membership witness is
$$
\mathsf{w}_e = g^{\prod_{x\in S\setminus\{e\}} (s+x)}.
$$

**Verification** uses one pairing:
$$
 e(\mathsf{w}_e, g^{s+e}) \stackrel{?}{=} e(\mathsf{Acc}(S), g).
$$

### Updates

Appending $y$ should transform
$$
\mathsf{Acc}(S\cup\{y\}) = \mathsf{Acc}(S)^{(s+y)}.
$$
But exponent $(s+y)$ is *unknown* publicly; thus:

* Without trapdoor access or extra update keys, **public updates are not possible from $\mathsf{Acc}(S)$ alone.**
* A manager (with $s$ or suitable update material) can compute the new accumulator and **re-issue** witnesses.

### Prover state & maintenance

* **Prover keeps:** either just $e$ (and fetches a fresh $\mathsf{w}_e$ each time), or the latest $\mathsf{w}_e$.
* **On each append:** existing $\mathsf{w}_e$ becomes invalid; requires re-issuance or heavy recomputation with secret $s$.

### (Non)membership

* **Membership:** supported (constant-size, one pairing).
* **Non-membership:** *not native.* Universal/non-membership variants exist but require additional structures (e.g., auxiliary accumulators or Bezout-style relations in pairing groups) and typically more parameters.

### Complexity

* **Witness size:** $O(1)$ group element.
* **Prover:** trivial if a manager serves updated witnesses; otherwise impractical (needs $s$).
* **Verifier:** constant pairings (usually one).
* **On-chain:** pairing precompile friendly; requires trusted setup (trapdoor $s$ or updatable SRS).

---

## 3. KZG-based set accumulators (polynomial commitments)

Use the characteristic polynomial of $S$ with a KZG commitment.

### Setup

Structured Reference String (SRS) for degree $\ge |S|$:
$$
\mathsf{SRS}=\big(g, g^\tau, g^{\tau^2},\ldots\big).
$$

### Accumulator

Characteristic polynomial
$$
f_S(x)=\prod_{e\in S} (x-e).
$$
Commitment
$$
\mathsf{Acc}(S)=C=g^{f_S(\tau)}.
$$

### Membership witness

For $e\in S$ define the quotient
$$
q_e(x)=\frac{f_S(x)}{x-e}.
$$
Witness
$$
\mathsf{w}_e = g^{q_e(\tau)}.
$$
**Verify** with one pairing:
$$
 e(\mathsf{w}_e, g^{\tau - e}) \stackrel{?}{=} e(C, g).
$$

### Non-membership witness (Bézout relation)

For $y\notin S$, find polynomials $u(x),v(x)$ with
$$
u(x)\cdot f_S(x) + v(x)\cdot (x-y) = 1.
$$
Publish
$$
W_u = g^{u(\tau)}, \quad W_v = g^{v(\tau)}.
$$
**Verify**:
$$
 e(W_u, C)\cdot e(W_v, g^{\tau - y}) \stackrel{?}{=} e(g, g).
$$

### Updates

Appending $y$ changes $f_{S\cup\{y\}}(x)=f_S(x)(x-y)$ and
$$
C' = g^{f_S(\tau)(\tau-y)}.
$$
**Publicly deriving $C'$ from $C$ is *not* possible** without extra SRS material enabling multiplication by $(\tau-y)$. In practice:

* The *aggregator* recomputes $C'$ from coefficients (linear in $\deg f$) or maintains a product tree to keep it quasi-linear.
* Existing membership witnesses $\mathsf{w}_e$ must be **recomputed** or served as *updateable witnesses* if the system publishes update keys.

### Prover state & maintenance

* **Prover keeps:** element $e$ and most recent $\mathsf{w}_e$ (or fetches on demand).
* **On append:** witnesses stale; require server re-issuance. Public self-updates are not feasible without special keys.

### Complexity

* **Witness sizes:** constant ($G_1$ elements).
* **Prover:** light if served by aggregator; heavy otherwise.
* **Verifier:** constant pairings (1 for membership; 2 for non-membership as above).
* **Trust:** updatable/ceremony SRS; standard KZG assumptions.
* **On-chain:** excellent—BN254 pairing precompile.

---

## 4. RSA-based accumulators (unknown-order groups)

Accumulate primes in an unknown-order group; supports elegant public updates.

### Setup

* Choose RSA modulus $N$ with unknown factorization; generator $g\in \mathbb{Z}_N^*$.
* Map elements to primes via hash-to-prime $\mathsf{Hp}:\mathcal{U}\to \text{Primes}$.

### Accumulator and membership

Let $X=\prod_{e\in S}\mathsf{Hp}(e)$. Define
$$
\mathsf{Acc}(S)=A=g^X \bmod N.
$$
Membership witness for $e\in S$:
$$
\mathsf{w}_e = g^{X/\mathsf{Hp}(e)} \bmod N.
$$
**Verify** with one modexp:
$$
\mathsf{w}_e^{\mathsf{Hp}(e)} \stackrel{?}{\equiv} A \pmod N.
$$

### Public append (key advantage)

Append $y$ with prime $p_y=\mathsf{Hp}(y)$:
$$
A' = A^{p_y} \pmod N.
$$
Existing witnesses *publicly update* as
$$
\mathsf{w}_e' = \mathsf{w}_e^{p_y} \pmod N,\quad
\text{and } \mathsf{w}_y = A.
$$
No trapdoor required; everyone can update locally.

### Non-membership (universal accumulator)

Let $p=\mathsf{Hp}(y)$ and $X=\prod_{e\in S}\mathsf{Hp}(e)$ (note $\gcd(p,X)=1$ if $y\notin S$). Find integers $(a,b)$ s.t.
$$
a\cdot p + b\cdot X = 1.
$$
Set
$$
d = g^a \bmod N,\quad \text{witness } (d,b).
$$
**Verify**:
$$
d^{p}\cdot A^{b} \stackrel{?}{\equiv} g \pmod N.
$$

### Prover state & maintenance

* **Prover keeps:** a membership witness $\mathsf{w}_e$ that can be *locally* updated for each append (raise to $p_y$).
* **Non-membership:** computing $(a,b)$ requires Bezout on $(p,X)$—practical with a *subset-product tree* or server assistance (you need $X$ modulo $p$).

### Complexity

* **Witness size:** $O(1)$ (one or two $\bmod N$ elements).
* **Append & witness updates:** $O(1)$ modular exponentiations *publicly*.
* **Verifier:** one modular exponent for membership; a couple for non-membership.
* **Trust:** strong RSA/unknown-order assumption; classic variant needs sound hash-to-prime, while the Kemmoe–Lysyanskaya variant avoids hashing to primes.
* **On-chain:** uses `modexp` precompile; gas is materially higher than BN254 pairing, but append & client updates are superb off chain.

### Variant: no hash-to-prime (Kemmoe–Lysyanskaya, 2024)

Kemmoe and Lysyanskaya (CCS 2024; IACR ePrint 2024/505) give an RSA-based **dynamic universal** accumulator that **does not require mapping elements to primes**. Elements can be accumulated in their native representation, while retaining constant-size witnesses and efficient verification in the unknown-order group. This removes the hash-to-prime step (and its engineering overhead) yet keeps **public append** semantics characteristic of RSA accumulators.

*EVM note:* Verification still uses modular exponentiation via the `modexp` precompile. On-chain costs are comparable to classic RSA accumulators (pairing-based schemes are typically cheaper to verify on BN254 but lack public-update UX). The main benefit here is **eliminating hash-to-prime** in the client stack.

---

## Summary & Comparisons

### Feature matrix (qualitative)

| Accumulator               | Setup trust              | Proof size  | Verify cost (EVM)  | Append (public?)       | Witness upkeep on append         | Non-membership           | Deletions         | Typical fit for ZK nullifiers                                           |
| ------------------------- | ------------------------ | ----------- | ------------------ | ---------------------- | -------------------------------- | ------------------------ | ----------------- | ----------------------------------------------------------------------- |
| Sparse Merkle Tree        | None                     | $O(\log U)$ | $O(\log U)$ hashes | Yes                    | Needs path refresh ($O(\log U)$) | Yes (sparse default)     | Hard (but doable) | Simple, robust, cheap gas per leaf; larger proofs                       |
| Pairing-based (Nguyen/BB) | Trapdoor $s$ (or SRS)    | $O(1)$      | Few pairings       | **No** (needs manager) | Re-issue each time               | Not native (needs extra) | Non-trivial       | Great on-chain verify; operationally needs a witness server             |
| KZG set accumulator       | SRS (KZG)                | $O(1)$      | 1–2 pairings       | **No** (needs manager) | Re-issue each time               | **Yes** (Bézout)         | Non-trivial       | Best constant-size with native non-membership; needs server for updates |
| RSA accumulator           | None (but unknown-order) | $O(1)$      | Modexp (costly)    | **Yes** (public)       | **Local $O(1)$** power-up        | **Yes** (Bezout)         | Possible          | Superb client-side UX; on-chain verify heavier than pairings            |

> $U$ = keyspace size (e.g., $2^{256}$).

### High-level guidance

* **If you want minimal on-chain gas per proof and constant sizes:** KZG or pairing-based on BN254 are natural (pairing precompile). But you must operate a **witness update service**.
* **If you value self-updating client witnesses and trust-minimal setup:** RSA accumulators shine off chain; on chain, membership verification is heavier.
* **If you need no ceremonies and easy non-membership with simple infra:** Sparse Merkle Trees are operationally simple, with predictable on-chain costs that grow $\log U$.

---

## Security & Engineering Notes

* **Domain separation:** hash nullifiers into the accumulator’s field/group domain (and to primes for RSA).
* **Soundness vs collisions:** Merkle depends on the hash; KZG/pairing depend on discrete-log/bilinear assumptions; RSA depends on Strong RSA/unknown order and secure $\mathsf{Hp}$.
* **Batching:** all families support batching tricks (multi-openings for KZG, multi-pairing equations, Merkle multiproofs, batched modexp for RSA).
* **Persistence:** store only the accumulator and (optionally) a recent epoch number to help clients coordinate witness updates.
* **Deletions:** not needed for nullifiers; if ever required, SMTs handle it; RSA and pairing/KZG require specialized protocols.

---

## Appendix A — Formal details

### Sparse Merkle verification

For sibling list $\pi_e=(s_0,\dots,s_{d-1})$ and bit-decomposition of $i=\mathsf{H}(e)$, define
$$
 h_0 = \mathsf{H}(\textsf{leaf}(e)),\quad
 h_{k+1}=\begin{cases}
  \mathsf{H}(h_k \| s_k) & \text{if } i_k=0 \\
  \mathsf{H}(s_k \| h_k) & \text{if } i_k=1
 \end{cases}
$$
Accept if $h_d=R$.

### Pairing-based membership check

$$
 e(\mathsf{w}_e, g^{s+e}) \stackrel{?}{=} e(\mathsf{Acc}(S), g).
$$

### KZG membership & non-membership

Membership:
$$
 e\!\left(g^{q_e(\tau)}, g^{\tau-e}\right) \stackrel{?}{=} e\!\left(g^{f_S(\tau)}, g\right).
$$

Non-membership (Bézout):
$$
 e\!\left(g^{u(\tau)}, g^{f_S(\tau)}\right)\cdot e\!\left(g^{v(\tau)}, g^{\tau-y}\right) \stackrel{?}{=} e(g,g).
$$

### RSA membership & non-membership

Membership:
$$
\left(\mathsf{w}_e\right)^{\mathsf{Hp}(e)} \stackrel{?}{\equiv} \mathsf{Acc}(S) \pmod N.
$$

Non-membership:
$$
d^{\mathsf{Hp}(y)}\cdot \mathsf{Acc}(S)^{b} \stackrel{?}{\equiv} g \pmod N
\quad\text{where } a\cdot \mathsf{Hp}(y)+b\cdot X=1,\ d=g^a.
$$

---

## Appendix B — Complexity summary (asymptotic)

Let $n=|S|$ and depth $d=\log U$.

* **SMT**

  * Witness size: $O(d)$.
  * Append: $O(d)$ recomputations.
  * Verify: $O(d)$ hashes.
* **Pairing-based**

  * Witness size: $O(1)$.
  * Append: needs manager; public append from digest alone not possible.
  * Verify: $O(1)$ pairings.
* **KZG**

  * Witness size: $O(1)$.
  * Append: needs manager (or special update keys).
  * Verify: membership $1$ pairing; non-membership $2$ pairings.
* **RSA**

  * Witness size: $O(1)$.
  * Append: **public $O(1)$** modexp; witnesses power-up locally.
  * Verify: $O(1)$ modexp (membership), $O(1)$ more (non-membership).

---

## Practical design patterns for ZK nullifiers

* **On-chain minimalism:** store only $\mathsf{Acc}(S)$ and an epoch counter.
* **Off-chain service:** for KZG/pairing variants, run a stateless *witness distributor* that (a) recomputes $C$ on append, (b) serves fresh $\mathsf{w}_e$.
* **Client-friendly option:** RSA accumulators let wallets update their own witnesses when new nullifiers appear—great UX if on-chain modexp is acceptable.
* **Straightforward & ceremony-free:** SMTs with Poseidon give ZK-friendly hashing and predictable EVM verification with a loop over $d$ hashes.

---

## Final thoughts

No single accumulator dominates across all axes. For *EVM-first, constant-size proofs and low verify gas*, **KZG** (with Bézout non-membership) or **pairing-based** are the front-runners—provided you can operate a reliable witness update channel. For **trust-minimal client UX with self-updating witnesses**, **RSA accumulators** are compelling, trading higher on-chain verify cost for clean off-chain ergonomics. When **simplicity and zero ceremonies** matter most, **Sparse Merkle Trees** remain an excellent baseline.

> Next steps you might want to add: concrete gas benchmarks per operation (pairings vs keccak/poseidon vs modexp), serialization formats, and reference code stubs (Solidity + Rust) for each family.


## References

1. R. C. Merkle. *A Digital Signature Based on a Conventional Encryption Function*. CRYPTO 1987.
2. J. Benaloh and M. de Mare. *One-Way Accumulators: A Decentralized Alternative to Digital Signatures*. EUROCRYPT 1993.
3. J. Camenisch and A. Lysyanskaya. *Dynamic Accumulators and Application to Efficient Revocation of Anonymous Credentials*. CRYPTO 2002.
4. L. Nguyen. *Accumulators from Bilinear Pairings and Applications*. CT-RSA 2005.
5. A. Kate, G. Zaverucha, I. Goldberg. *Constant-Size Commitments to Polynomials and Their Applications*. ASIACRYPT 2010. (KZG)
6. A. Bünz, S. Eskandarian, D. Boneh. *Proofs of Liabilities/Reserves* and related set-accumulator techniques (2018–2019 notes/surveys).
7. V. Y. Kemmoe and A. Lysyanskaya. *RSA-Based Dynamic Accumulator without Hashing into Primes*. CCS 2024; IACR ePrint 2024/505.
