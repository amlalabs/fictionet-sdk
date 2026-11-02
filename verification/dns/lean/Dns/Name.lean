/-
  Domain names: labels as byte lists, the ASCII case fold, the canonical order of RFC 4034 §6.1, the
  "at or below" relation, and the 255-octet limit of RFC 1035 §2.3.4.

  A name is its list of labels, leftmost first, without the empty root label, so the root is `[]` and
  `www.example.com.` is `[www, example, com]`. Bytes are `Nat`s; the theorems that need them to be octets
  say so.

  Rust: `LowerName` in hickory, with `Name::cmp_canonical`, `zone_of`, and `len`.
-/
namespace Dns

abbrev Bytes := List Nat
abbrev Label := List Nat
abbrev Name := List Label

namespace Name

/-! ## Case folding (RFC 4343 §3) -/

/-- ASCII lowercase: `A` to `Z` become `a` to `z`; every other octet stays. -/
def foldByte (b : Nat) : Nat := if 65 ≤ b ∧ b ≤ 90 then b + 32 else b

def foldLabel (l : Label) : Label := l.map foldByte

def fold (n : Name) : Name := n.map foldLabel

theorem foldByte_idem (b : Nat) : foldByte (foldByte b) = foldByte b := by
  unfold foldByte; split <;> (try split) <;> omega

theorem foldLabel_idem (l : Label) : foldLabel (foldLabel l) = foldLabel l := by
  simp [foldLabel, Function.comp_def, foldByte_idem]

theorem fold_idem (n : Name) : fold (fold n) = fold n := by
  simp [fold, Function.comp_def, foldLabel_idem]

@[simp] theorem foldLabel_length (l : Label) : (foldLabel l).length = l.length := by simp [foldLabel]
@[simp] theorem fold_length (n : Name) : (fold n).length = n.length := by simp [fold]

/-! ## Case-insensitive equality

`eqCI` compares octet by octet, the way a server compares a question with a name it holds. -/

def labelEqCI : Label → Label → Bool
  | [], [] => true
  | a :: as, b :: bs => foldByte a == foldByte b && labelEqCI as bs
  | _, _ => false

def eqCI : Name → Name → Bool
  | [], [] => true
  | a :: as, b :: bs => labelEqCI a b && eqCI as bs
  | _, _ => false

theorem labelEqCI_iff (a b : Label) : labelEqCI a b = true ↔ foldLabel a = foldLabel b := by
  induction a generalizing b with
  | nil => cases b <;> simp [labelEqCI, foldLabel]
  | cons x xs ih =>
    cases b with
    | nil => simp [labelEqCI, foldLabel]
    | cons y ys =>
      have := ih ys
      simp only [labelEqCI, Bool.and_eq_true, beq_iff_eq, foldLabel, List.map_cons, List.cons.injEq] at this ⊢
      rw [this]

theorem eqCI_iff_fold_eq (a b : Name) : eqCI a b = true ↔ fold a = fold b := by
  induction a generalizing b with
  | nil => cases b <;> simp [eqCI, fold]
  | cons x xs ih =>
    cases b with
    | nil => simp [eqCI, fold]
    | cons y ys =>
      have := ih ys
      simp only [eqCI, Bool.and_eq_true, fold, List.map_cons, List.cons.injEq] at this ⊢
      rw [labelEqCI_iff, this]

/-! ## Canonical order (RFC 4034 §6.1)

Names sort by their labels from the rightmost, each label compared as a lowercase octet string in which a
missing octet sorts before every present one; a name that runs out of labels first sorts first. -/

/-- Lexicographic order on octet strings: a proper prefix sorts first. -/
def labelLt : Label → Label → Bool
  | [], [] => false
  | [], _ :: _ => true
  | _ :: _, [] => false
  | a :: as, b :: bs => a < b || (a == b && labelLt as bs)

/-- Lexicographic order on label sequences, most significant label first. -/
def labelsLt : List Label → List Label → Bool
  | [], [] => false
  | [], _ :: _ => true
  | _ :: _, [] => false
  | a :: as, b :: bs => labelLt a b || (a == b && labelsLt as bs)

def canonLt (a b : Name) : Bool := labelsLt (fold a).reverse (fold b).reverse

/-- The three-way comparison the vectors report: `-1`, `0`, or `1`. -/
def canonCmp (a b : Name) : Int :=
  if canonLt a b then -1 else if canonLt b a then 1 else 0

theorem labelLt_irrefl (a : Label) : labelLt a a = false := by
  induction a with
  | nil => rfl
  | cons x xs ih => simp [labelLt, ih]

theorem labelLt_total (a b : Label) : labelLt a b = true ∨ a = b ∨ labelLt b a = true := by
  induction a generalizing b with
  | nil => cases b <;> simp [labelLt]
  | cons x xs ih =>
    cases b with
    | nil => simp [labelLt]
    | cons y ys =>
      simp only [labelLt, Bool.or_eq_true, decide_eq_true_eq, Bool.and_eq_true, beq_iff_eq,
        List.cons.injEq]
      rcases Nat.lt_trichotomy x y with h | h | h
      · exact Or.inl (Or.inl h)
      · subst h; rcases ih ys with h' | h' | h'
        · exact Or.inl (Or.inr ⟨rfl, h'⟩)
        · exact Or.inr (Or.inl ⟨rfl, h'⟩)
        · exact Or.inr (Or.inr (Or.inr ⟨rfl, h'⟩))
      · exact Or.inr (Or.inr (Or.inl h))

theorem labelLt_trans (a b c : Label) (h1 : labelLt a b = true) (h2 : labelLt b c = true) :
    labelLt a c = true := by
  induction a generalizing b c with
  | nil => cases b <;> cases c <;> simp_all [labelLt]
  | cons x xs ih =>
    cases b with
    | nil => simp [labelLt] at h1
    | cons y ys =>
      cases c with
      | nil => simp [labelLt] at h2
      | cons z zs =>
        simp only [labelLt, Bool.or_eq_true, decide_eq_true_eq, Bool.and_eq_true, beq_iff_eq] at *
        rcases h1 with h1 | ⟨rfl, h1⟩ <;> rcases h2 with h2 | ⟨rfl, h2⟩
        · exact Or.inl (Nat.lt_trans h1 h2)
        · exact Or.inl h1
        · exact Or.inl h2
        · exact Or.inr ⟨rfl, ih _ _ h1 h2⟩

theorem labelsLt_irrefl (a : List Label) : labelsLt a a = false := by
  induction a with
  | nil => rfl
  | cons x xs ih => simp [labelsLt, ih, labelLt_irrefl]

theorem labelsLt_total (a b : List Label) : labelsLt a b = true ∨ a = b ∨ labelsLt b a = true := by
  induction a generalizing b with
  | nil => cases b <;> simp [labelsLt]
  | cons x xs ih =>
    cases b with
    | nil => simp [labelsLt]
    | cons y ys =>
      simp only [labelsLt, Bool.or_eq_true, Bool.and_eq_true, beq_iff_eq, List.cons.injEq]
      rcases labelLt_total x y with h | h | h
      · exact Or.inl (Or.inl h)
      · subst h; rcases ih ys with h' | h' | h'
        · exact Or.inl (Or.inr ⟨rfl, h'⟩)
        · exact Or.inr (Or.inl ⟨rfl, h'⟩)
        · exact Or.inr (Or.inr (Or.inr ⟨rfl, h'⟩))
      · exact Or.inr (Or.inr (Or.inl h))

theorem labelsLt_trans (a b c : List Label) (h1 : labelsLt a b = true) (h2 : labelsLt b c = true) :
    labelsLt a c = true := by
  induction a generalizing b c with
  | nil => cases b <;> cases c <;> simp_all [labelsLt]
  | cons x xs ih =>
    cases b with
    | nil => simp [labelsLt] at h1
    | cons y ys =>
      cases c with
      | nil => simp [labelsLt] at h2
      | cons z zs =>
        simp only [labelsLt, Bool.or_eq_true, Bool.and_eq_true, beq_iff_eq] at *
        rcases h1 with h1 | ⟨rfl, h1⟩ <;> rcases h2 with h2 | ⟨rfl, h2⟩
        · exact Or.inl (labelLt_trans _ _ _ h1 h2)
        · exact Or.inl h1
        · exact Or.inl h2
        · exact Or.inr ⟨rfl, ih _ _ h1 h2⟩

/-- Any two names are ordered one way, or equal up to case. -/
theorem canon_total (a b : Name) : canonLt a b = true ∨ fold a = fold b ∨ canonLt b a = true := by
  unfold canonLt
  rcases labelsLt_total (fold a).reverse (fold b).reverse with h | h | h
  · exact Or.inl h
  · exact Or.inr (Or.inl (List.reverse_inj.mp h))
  · exact Or.inr (Or.inr h)

theorem canon_lt_trans (a b c : Name) (h1 : canonLt a b = true) (h2 : canonLt b c = true) :
    canonLt a c = true :=
  labelsLt_trans _ _ _ h1 h2

theorem canon_lt_irrefl (a : Name) : canonLt a a = false := labelsLt_irrefl _

/-- Names equal up to case sort the same. -/
theorem canonLt_fold_left (a b : Name) : canonLt (fold a) b = canonLt a b := by
  simp [canonLt, fold_idem]

/-! ## At or below

`a` is at or below `b` when `b`'s labels are a suffix of `a`'s, up to case. `example.com.` is at or below
`com.` and at or below itself; every name is at or below the root. -/

def below (a b : Name) : Bool := (fold b).isSuffixOf (fold a)

theorem below_iff (a b : Name) : below a b = true ↔ fold b <:+ fold a := List.isSuffixOf_iff_suffix

theorem below_refl (a : Name) : below a a = true := (below_iff a a).mpr (List.suffix_refl _)

theorem below_trans (a b c : Name) (h1 : below a b = true) (h2 : below b c = true) :
    below a c = true :=
  (below_iff a c).mpr (((below_iff b c).mp h2).trans ((below_iff a b).mp h1))

theorem below_root (a : Name) : below a [] = true := (below_iff a []).mpr (List.nil_suffix)

/-! ## Length on the wire (RFC 1035 §2.3.4, §3.1)

Each label takes its length octet plus its octets, and the root label takes one octet. A name may take at
most 255 octets and a label at most 63. -/

def wireLen (n : Name) : Nat := (n.map fun l => l.length + 1).sum + 1

@[simp] theorem wireLen_nil : wireLen [] = 1 := rfl
@[simp] theorem wireLen_cons (l : Label) (n : Name) : wireLen (l :: n) = l.length + 1 + wireLen n := by
  simp [wireLen]; omega

theorem wireLen_fold (n : Name) : wireLen (fold n) = wireLen n := by
  induction n with
  | nil => rfl
  | cons l n ih => simp only [fold, List.map_cons] at *; simp [ih]

/-- A label is well formed when it has 1 to 63 octets, each below 256. -/
def labelOk (l : Label) : Bool := 0 < l.length && l.length ≤ 63 && l.all (· < 256)

/-- The label-by-label check a parser applies: it adds each label's octets to a running total and stops
as soon as a label is malformed or the total passes 255. -/
def checkLabels : List Label → Nat → Bool
  | [], used => used + 1 ≤ 255
  | l :: ls, used => labelOk l && used + l.length + 1 + 1 ≤ 255 && checkLabels ls (used + l.length + 1)

/-- The name with these labels, if they make a legal name. -/
def ofLabels? (ls : List Label) : Option Name := if checkLabels ls 0 then some ls else none

/-- A well-formed name: every label legal and at most 255 octets in all. -/
def valid (n : Name) : Bool := n.all labelOk && wireLen n ≤ 255

theorem checkLabels_iff (ls : List Label) (used : Nat) :
    checkLabels ls used = true ↔ (ls.all labelOk = true ∧ used + wireLen ls ≤ 255) := by
  induction ls generalizing used with
  | nil => simp [checkLabels]
  | cons l ls ih =>
    simp only [checkLabels, Bool.and_eq_true, decide_eq_true_eq, ih, List.all_cons, wireLen_cons]
    have : 1 ≤ wireLen ls := by unfold wireLen; omega
    constructor
    · rintro ⟨⟨h1, _⟩, h3, h4⟩; exact ⟨⟨h1, h3⟩, by omega⟩
    · rintro ⟨⟨h1, h3⟩, h4⟩; exact ⟨⟨h1, by omega⟩, h3, by omega⟩

/-- A name the label-by-label check accepts fits in 255 octets, folding does not change its length, and the
check accepts exactly the valid names. -/
theorem wire_len_le_255 (ls : List Label) (n : Name) (h : ofLabels? ls = some n) :
    wireLen n ≤ 255 ∧ wireLen (fold n) = wireLen n ∧ valid n = true := by
  unfold ofLabels? at h
  split at h
  · rename_i hc
    cases h
    have := (checkLabels_iff _ 0).mp hc
    refine ⟨by omega, wireLen_fold _, ?_⟩
    simp [valid, this.1]; omega
  · cases h

theorem ofLabels?_complete (n : Name) (h : valid n = true) : ofLabels? n = some n := by
  simp only [valid, Bool.and_eq_true, decide_eq_true_eq] at h
  simp [ofLabels?, (checkLabels_iff n 0).mpr ⟨h.1, by omega⟩]

end Name
end Dns
