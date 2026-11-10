import Hpack.Int

/-!
# Huffman strings (RFC 7541 section 5.2 and Appendix B)

`codeTable` is Appendix B, row by row, taken from the RFC text: each
symbol's code and length, EOS last. `tree` is the binary tree those codes
make; three facts about it are checked by the kernel (`paths_ok`,
`leaves_ok`, `ones_ok`). `decode` walks the tree bit by bit as section 5.2
says, with the order of checks the Rust decoder (`huffman::decode_limited`)
has: EOS is refused when it is reached, a symbol past the limit is refused
when it is reached, and at the end at most seven bits may be left, all ones.
-/

namespace Hpack

/-- RFC 7541 Appendix B, row by row: each symbol's code and its length in bits. -/
def codeTable : List (Nat × Nat) := [
  (0x1ff8, 13), -- 0
  (0x7fffd8, 23), -- 1
  (0xfffffe2, 28), -- 2
  (0xfffffe3, 28), -- 3
  (0xfffffe4, 28), -- 4
  (0xfffffe5, 28), -- 5
  (0xfffffe6, 28), -- 6
  (0xfffffe7, 28), -- 7
  (0xfffffe8, 28), -- 8
  (0xffffea, 24), -- 9
  (0x3ffffffc, 30), -- 10
  (0xfffffe9, 28), -- 11
  (0xfffffea, 28), -- 12
  (0x3ffffffd, 30), -- 13
  (0xfffffeb, 28), -- 14
  (0xfffffec, 28), -- 15
  (0xfffffed, 28), -- 16
  (0xfffffee, 28), -- 17
  (0xfffffef, 28), -- 18
  (0xffffff0, 28), -- 19
  (0xffffff1, 28), -- 20
  (0xffffff2, 28), -- 21
  (0x3ffffffe, 30), -- 22
  (0xffffff3, 28), -- 23
  (0xffffff4, 28), -- 24
  (0xffffff5, 28), -- 25
  (0xffffff6, 28), -- 26
  (0xffffff7, 28), -- 27
  (0xffffff8, 28), -- 28
  (0xffffff9, 28), -- 29
  (0xffffffa, 28), -- 30
  (0xffffffb, 28), -- 31
  (0x14, 6), -- 32
  (0x3f8, 10), -- 33
  (0x3f9, 10), -- 34
  (0xffa, 12), -- 35
  (0x1ff9, 13), -- 36
  (0x15, 6), -- 37
  (0xf8, 8), -- 38
  (0x7fa, 11), -- 39
  (0x3fa, 10), -- 40
  (0x3fb, 10), -- 41
  (0xf9, 8), -- 42
  (0x7fb, 11), -- 43
  (0xfa, 8), -- 44
  (0x16, 6), -- 45
  (0x17, 6), -- 46
  (0x18, 6), -- 47
  (0x0, 5), -- 48
  (0x1, 5), -- 49
  (0x2, 5), -- 50
  (0x19, 6), -- 51
  (0x1a, 6), -- 52
  (0x1b, 6), -- 53
  (0x1c, 6), -- 54
  (0x1d, 6), -- 55
  (0x1e, 6), -- 56
  (0x1f, 6), -- 57
  (0x5c, 7), -- 58
  (0xfb, 8), -- 59
  (0x7ffc, 15), -- 60
  (0x20, 6), -- 61
  (0xffb, 12), -- 62
  (0x3fc, 10), -- 63
  (0x1ffa, 13), -- 64
  (0x21, 6), -- 65
  (0x5d, 7), -- 66
  (0x5e, 7), -- 67
  (0x5f, 7), -- 68
  (0x60, 7), -- 69
  (0x61, 7), -- 70
  (0x62, 7), -- 71
  (0x63, 7), -- 72
  (0x64, 7), -- 73
  (0x65, 7), -- 74
  (0x66, 7), -- 75
  (0x67, 7), -- 76
  (0x68, 7), -- 77
  (0x69, 7), -- 78
  (0x6a, 7), -- 79
  (0x6b, 7), -- 80
  (0x6c, 7), -- 81
  (0x6d, 7), -- 82
  (0x6e, 7), -- 83
  (0x6f, 7), -- 84
  (0x70, 7), -- 85
  (0x71, 7), -- 86
  (0x72, 7), -- 87
  (0xfc, 8), -- 88
  (0x73, 7), -- 89
  (0xfd, 8), -- 90
  (0x1ffb, 13), -- 91
  (0x7fff0, 19), -- 92
  (0x1ffc, 13), -- 93
  (0x3ffc, 14), -- 94
  (0x22, 6), -- 95
  (0x7ffd, 15), -- 96
  (0x3, 5), -- 97
  (0x23, 6), -- 98
  (0x4, 5), -- 99
  (0x24, 6), -- 100
  (0x5, 5), -- 101
  (0x25, 6), -- 102
  (0x26, 6), -- 103
  (0x27, 6), -- 104
  (0x6, 5), -- 105
  (0x74, 7), -- 106
  (0x75, 7), -- 107
  (0x28, 6), -- 108
  (0x29, 6), -- 109
  (0x2a, 6), -- 110
  (0x7, 5), -- 111
  (0x2b, 6), -- 112
  (0x76, 7), -- 113
  (0x2c, 6), -- 114
  (0x8, 5), -- 115
  (0x9, 5), -- 116
  (0x2d, 6), -- 117
  (0x77, 7), -- 118
  (0x78, 7), -- 119
  (0x79, 7), -- 120
  (0x7a, 7), -- 121
  (0x7b, 7), -- 122
  (0x7ffe, 15), -- 123
  (0x7fc, 11), -- 124
  (0x3ffd, 14), -- 125
  (0x1ffd, 13), -- 126
  (0xffffffc, 28), -- 127
  (0xfffe6, 20), -- 128
  (0x3fffd2, 22), -- 129
  (0xfffe7, 20), -- 130
  (0xfffe8, 20), -- 131
  (0x3fffd3, 22), -- 132
  (0x3fffd4, 22), -- 133
  (0x3fffd5, 22), -- 134
  (0x7fffd9, 23), -- 135
  (0x3fffd6, 22), -- 136
  (0x7fffda, 23), -- 137
  (0x7fffdb, 23), -- 138
  (0x7fffdc, 23), -- 139
  (0x7fffdd, 23), -- 140
  (0x7fffde, 23), -- 141
  (0xffffeb, 24), -- 142
  (0x7fffdf, 23), -- 143
  (0xffffec, 24), -- 144
  (0xffffed, 24), -- 145
  (0x3fffd7, 22), -- 146
  (0x7fffe0, 23), -- 147
  (0xffffee, 24), -- 148
  (0x7fffe1, 23), -- 149
  (0x7fffe2, 23), -- 150
  (0x7fffe3, 23), -- 151
  (0x7fffe4, 23), -- 152
  (0x1fffdc, 21), -- 153
  (0x3fffd8, 22), -- 154
  (0x7fffe5, 23), -- 155
  (0x3fffd9, 22), -- 156
  (0x7fffe6, 23), -- 157
  (0x7fffe7, 23), -- 158
  (0xffffef, 24), -- 159
  (0x3fffda, 22), -- 160
  (0x1fffdd, 21), -- 161
  (0xfffe9, 20), -- 162
  (0x3fffdb, 22), -- 163
  (0x3fffdc, 22), -- 164
  (0x7fffe8, 23), -- 165
  (0x7fffe9, 23), -- 166
  (0x1fffde, 21), -- 167
  (0x7fffea, 23), -- 168
  (0x3fffdd, 22), -- 169
  (0x3fffde, 22), -- 170
  (0xfffff0, 24), -- 171
  (0x1fffdf, 21), -- 172
  (0x3fffdf, 22), -- 173
  (0x7fffeb, 23), -- 174
  (0x7fffec, 23), -- 175
  (0x1fffe0, 21), -- 176
  (0x1fffe1, 21), -- 177
  (0x3fffe0, 22), -- 178
  (0x1fffe2, 21), -- 179
  (0x7fffed, 23), -- 180
  (0x3fffe1, 22), -- 181
  (0x7fffee, 23), -- 182
  (0x7fffef, 23), -- 183
  (0xfffea, 20), -- 184
  (0x3fffe2, 22), -- 185
  (0x3fffe3, 22), -- 186
  (0x3fffe4, 22), -- 187
  (0x7ffff0, 23), -- 188
  (0x3fffe5, 22), -- 189
  (0x3fffe6, 22), -- 190
  (0x7ffff1, 23), -- 191
  (0x3ffffe0, 26), -- 192
  (0x3ffffe1, 26), -- 193
  (0xfffeb, 20), -- 194
  (0x7fff1, 19), -- 195
  (0x3fffe7, 22), -- 196
  (0x7ffff2, 23), -- 197
  (0x3fffe8, 22), -- 198
  (0x1ffffec, 25), -- 199
  (0x3ffffe2, 26), -- 200
  (0x3ffffe3, 26), -- 201
  (0x3ffffe4, 26), -- 202
  (0x7ffffde, 27), -- 203
  (0x7ffffdf, 27), -- 204
  (0x3ffffe5, 26), -- 205
  (0xfffff1, 24), -- 206
  (0x1ffffed, 25), -- 207
  (0x7fff2, 19), -- 208
  (0x1fffe3, 21), -- 209
  (0x3ffffe6, 26), -- 210
  (0x7ffffe0, 27), -- 211
  (0x7ffffe1, 27), -- 212
  (0x3ffffe7, 26), -- 213
  (0x7ffffe2, 27), -- 214
  (0xfffff2, 24), -- 215
  (0x1fffe4, 21), -- 216
  (0x1fffe5, 21), -- 217
  (0x3ffffe8, 26), -- 218
  (0x3ffffe9, 26), -- 219
  (0xffffffd, 28), -- 220
  (0x7ffffe3, 27), -- 221
  (0x7ffffe4, 27), -- 222
  (0x7ffffe5, 27), -- 223
  (0xfffec, 20), -- 224
  (0xfffff3, 24), -- 225
  (0xfffed, 20), -- 226
  (0x1fffe6, 21), -- 227
  (0x3fffe9, 22), -- 228
  (0x1fffe7, 21), -- 229
  (0x1fffe8, 21), -- 230
  (0x7ffff3, 23), -- 231
  (0x3fffea, 22), -- 232
  (0x3fffeb, 22), -- 233
  (0x1ffffee, 25), -- 234
  (0x1ffffef, 25), -- 235
  (0xfffff4, 24), -- 236
  (0xfffff5, 24), -- 237
  (0x3ffffea, 26), -- 238
  (0x7ffff4, 23), -- 239
  (0x3ffffeb, 26), -- 240
  (0x7ffffe6, 27), -- 241
  (0x3ffffec, 26), -- 242
  (0x3ffffed, 26), -- 243
  (0x7ffffe7, 27), -- 244
  (0x7ffffe8, 27), -- 245
  (0x7ffffe9, 27), -- 246
  (0x7ffffea, 27), -- 247
  (0x7ffffeb, 27), -- 248
  (0xffffffe, 28), -- 249
  (0x7ffffec, 27), -- 250
  (0x7ffffed, 27), -- 251
  (0x7ffffee, 27), -- 252
  (0x7ffffef, 27), -- 253
  (0x7fffff0, 27), -- 254
  (0x3ffffee, 26), -- 255
  (0x3fffffff, 30) -- 256
]

/-! ## Bits and bytes -/

/-- The low `l` bits of `c`, most significant first. -/
def bitsOf (c : Nat) : Nat → List Bool
  | 0 => []
  | l + 1 => c.testBit l :: bitsOf c l

/-- The value of bits, most significant first. -/
def bitsVal : List Bool → Nat
  | [] => 0
  | b :: l => (if b then 2 ^ l.length else 0) + bitsVal l

/-- Bytes as bits, most significant first in each byte. -/
def unpack (bytes : Bytes) : List Bool := bytes.flatMap (fun b => bitsOf b 8)

/-- Bits as bytes, eight at a time. -/
def pack (bits : List Bool) : Bytes :=
  if h : bits.length < 8 then [] else bitsVal (bits.take 8) :: pack (bits.drop 8)
termination_by bits.length
decreasing_by simp; omega

theorem bitsOf_length (c l : Nat) : (bitsOf c l).length = l := by
  induction l with
  | zero => rfl
  | succ l ih => simp [bitsOf, ih]

/-- Eight bits make a byte that reads back as themselves. -/
theorem byte_bits : ∀ b0 b1 b2 b3 b4 b5 b6 b7 : Bool,
    bitsOf (bitsVal [b0, b1, b2, b3, b4, b5, b6, b7]) 8 = [b0, b1, b2, b3, b4, b5, b6, b7] ∧
    bitsVal [b0, b1, b2, b3, b4, b5, b6, b7] < 256 := by
  decide +kernel

/-- A byte's eight bits make the byte again. -/
theorem bits_byte : ∀ b, b < 256 → bitsVal (bitsOf b 8) = b := by
  decide +kernel

theorem unpack_pack (bits : List Bool) (h : bits.length % 8 = 0) : unpack (pack bits) = bits := by
  induction bits using pack.induct with
  | case1 bits hl =>
    rw [pack, dif_pos hl]
    have : bits.length = 0 := by omega
    simp [unpack, List.length_eq_zero_iff.mp this]
  | case2 bits hl ih =>
    rw [pack, dif_neg hl]
    have hd : (bits.drop 8).length % 8 = 0 := by simp; omega
    have key : ∀ l : List Bool, l.length = 8 → bitsOf (bitsVal l) 8 = l := by
      intro l hl8
      match l, hl8 with
      | [b0, b1, b2, b3, b4, b5, b6, b7], _ => exact (byte_bits b0 b1 b2 b3 b4 b5 b6 b7).1
    simp only [unpack, List.flatMap_cons] at ih ⊢
    rw [ih hd, key _ (by simp; omega), List.take_append_drop]

theorem pack_bytes (bits : List Bool) : ∀ b ∈ pack bits, b < 256 := by
  induction bits using pack.induct with
  | case1 bits hl => rw [pack, dif_pos hl]; simp
  | case2 bits hl ih =>
    rw [pack, dif_neg hl]
    intro b hb
    simp only [List.mem_cons] at hb
    rcases hb with rfl | hb
    · have hl8 : (bits.take 8).length = 8 := by simp; omega
      match h : bits.take 8, hl8 with
      | [b0, b1, b2, b3, b4, b5, b6, b7], _ => exact (byte_bits b0 b1 b2 b3 b4 b5 b6 b7).2
    · exact ih b hb

theorem pack_unpack (bytes : Bytes) (h : ∀ b ∈ bytes, b < 256) : pack (unpack bytes) = bytes := by
  induction bytes with
  | nil => simp [unpack, pack]
  | cons b rest ih =>
    simp only [unpack, List.flatMap_cons] at ih ⊢
    rw [pack, dif_neg (by simp [bitsOf_length])]
    have h8 : (bitsOf b 8).length = 8 := bitsOf_length b 8
    rw [List.take_append_of_le_length (by omega), List.take_of_length_le (by omega),
      List.drop_append_of_le_length (by omega), List.drop_of_length_le (by omega),
      List.nil_append, bits_byte b (h b (by simp)), ih (fun x hx => h x (by simp [hx]))]

theorem unpack_length (bytes : Bytes) : (unpack bytes).length = 8 * bytes.length := by
  induction bytes with
  | nil => rfl
  | cons b rest ih =>
    simp only [unpack, List.flatMap_cons, List.length_append, bitsOf_length] at ih ⊢
    simp only [List.length_cons]; omega

/-! ## The code -/

/-- Symbol `s`'s code and its length. -/
def codeOf (s : Nat) : Nat × Nat := codeTable.getD s (0, 0)

/-- Symbol `s`'s code as bits. -/
def codeBits (s : Nat) : List Bool := bitsOf (codeOf s).1 (codeOf s).2

/-- The end-of-string symbol. -/
def eos : Nat := 256

/-- A binary tree of codes: a leaf is a symbol, `empty` no code. -/
inductive Tree where
  | leaf (s : Nat)
  | node (zero one : Tree)
  | empty
  deriving DecidableEq, Repr

def Tree.child : Tree → Bool → Tree
  | .node z o, b => if b then o else z
  | _, _ => .empty

def Tree.walk (t : Tree) : List Bool → Tree
  | [] => t
  | b :: bs => (t.child b).walk bs

def Tree.insert : Tree → List Bool → Nat → Tree
  | _, [], s => .leaf s
  | .node z o, b :: bs, s => if b then .node z (o.insert bs s) else .node (z.insert bs s) o
  | _, b :: bs, s => if b then .node .empty (Tree.empty.insert bs s)
                      else .node (Tree.empty.insert bs s) .empty

def Tree.isNode : Tree → Bool
  | .node _ _ => true
  | _ => false

/-- Every leaf with the path to it. -/
def Tree.leaves : Tree → List (List Bool × Nat)
  | .leaf s => [([], s)]
  | .node z o => z.leaves.map (fun (p, s) => (false :: p, s)) ++
                 o.leaves.map (fun (p, s) => (true :: p, s))
  | .empty => []

/-- The tree of every code in Appendix B. -/
def tree : Tree := (List.range 257).foldl (fun t s => t.insert (codeBits s) s) .empty

/-- Each symbol's code leads to that symbol: the codes are distinct and none is
the start of another. -/
theorem paths_ok : (List.range 257).all (fun s => tree.walk (codeBits s) == .leaf s) = true := by
  decide +kernel

/-- Every leaf is a symbol of the table, reached by its own code. -/
theorem leaves_ok : tree.leaves.all (fun (p, s) => s < 257 && p == codeBits s) = true := by
  decide +kernel

/-- Up to 29 one bits lead inside the tree; 30 lead to EOS. -/
theorem ones_ok : (List.range 30).all (fun k => (tree.walk (List.replicate k true)).isNode) = true ∧
    tree.walk (List.replicate 30 true) = .leaf eos := by
  decide +kernel

/-- The code lengths are those of Appendix B: from 5 to 30 bits. -/
theorem code_lengths : (List.range 257).all (fun s => 5 ≤ (codeOf s).2 && (codeOf s).2 ≤ 30) = true := by
  decide +kernel

/-! ## Encoding and decoding -/

/-- The codes of the octets in order. -/
def encodeBits (s : List Nat) : List Bool := s.flatMap codeBits

/-- The bits that fill the last byte. -/
def padLen (n : Nat) : Nat := (8 - n % 8) % 8

/-- Section 5.2 encoding: the codes, then the most significant bits of EOS (ones)
to the byte boundary. -/
def encode (s : List Nat) : Bytes :=
  pack (encodeBits s ++ List.replicate (padLen (encodeBits s).length) true)

/-- Why a Huffman string could not be read: an invalid code, EOS or padding
(`huffman::Error::InvalidCode`), or more octets than the limit (`TooLong`). -/
inductive HuffError where
  | invalid
  | tooLong
  deriving DecidableEq, Repr

/-- The decoder: `t` is where the walk is, `depth` the bits since the last symbol,
`ones` whether they were all ones, `count` the octets so far, `out` them reversed. -/
def decodeBits (limit : Nat) : List Bool → Tree → Nat → Bool → Nat → List Nat →
    Except HuffError (List Nat)
  | [], _, depth, ones, _, out =>
    if depth < 8 ∧ ones = true then .ok out.reverse else .error .invalid
  | b :: bs, t, depth, ones, count, out =>
    match t.child b with
    | .leaf s =>
      if s = eos then .error .invalid
      else if limit ≤ count then .error .tooLong
      else decodeBits limit bs tree 0 true (count + 1) (s :: out)
    | .node z o => decodeBits limit bs (.node z o) (depth + 1) (ones && b) count out
    | .empty => .error .invalid

/-- Section 5.2 decoding of a whole string, at most `limit` octets. -/
def decode (limit : Nat) (bytes : Bytes) : Except HuffError (List Nat) :=
  decodeBits limit (unpack bytes) tree 0 true 0 []

/-! ## Facts about the tree -/

theorem walk_empty (p : List Bool) : Tree.empty.walk p = .empty := by
  induction p with
  | nil => rfl
  | cons b p ih => simpa [Tree.walk, Tree.child] using ih

theorem walk_leaf (s : Nat) (b : Bool) (p : List Bool) : (Tree.leaf s).walk (b :: p) = .empty := by
  simp [Tree.walk, Tree.child, walk_empty]

theorem walk_append (t : Tree) (p : List Bool) (b : Bool) :
    t.walk (p ++ [b]) = (t.walk p).child b := by
  induction p generalizing t with
  | nil => rfl
  | cons c p ih => exact ih _

/-- A walk that ends on a leaf went through nodes only. -/
theorem walk_to_leaf (t : Tree) (b : Bool) (p : List Bool) (s : Nat)
    (h : t.walk (b :: p) = .leaf s) :
    (p = [] ∧ t.child b = .leaf s) ∨ (∃ z o, t.child b = .node z o ∧ (Tree.node z o).walk p = .leaf s) := by
  simp only [Tree.walk] at h
  cases p with
  | nil => left; exact ⟨rfl, h⟩
  | cons c q =>
    right
    match hc : t.child b with
    | .leaf y => rw [hc, walk_leaf] at h; cases h
    | .empty => rw [hc, walk_empty] at h; cases h
    | .node z o => exact ⟨z, o, rfl, by rw [hc] at h; exact h⟩

theorem walk_leaves (t : Tree) (p : List Bool) (s : Nat) (h : t.walk p = .leaf s) :
    (p, s) ∈ t.leaves := by
  induction p generalizing t with
  | nil => simp [Tree.walk] at h; subst h; simp [Tree.leaves]
  | cons b p ih =>
    simp only [Tree.walk] at h
    match t, b with
    | .node z o, true =>
      simp only [Tree.child, ite_true] at h
      simp only [Tree.leaves, List.mem_append, List.mem_map]
      exact Or.inr ⟨(p, s), ih o h, rfl⟩
    | .node z o, false =>
      simp only [Tree.child] at h
      simp only [Tree.leaves, List.mem_append, List.mem_map]
      exact Or.inl ⟨(p, s), ih z h, rfl⟩
    | .leaf _, _ => simp [Tree.child, walk_empty] at h
    | .empty, _ => simp [Tree.child, walk_empty] at h

/-- A path through the tree to a leaf is exactly that symbol's code. -/
theorem tree_leaf_code (p : List Bool) (s : Nat) (h : tree.walk p = .leaf s) :
    s < 257 ∧ p = codeBits s := by
  have hm := walk_leaves tree p s h
  have := List.all_eq_true.mp leaves_ok _ hm
  simp only [Bool.and_eq_true, decide_eq_true_eq, beq_iff_eq] at this
  exact this

theorem tree_code (s : Nat) (h : s < 257) : tree.walk (codeBits s) = .leaf s := by
  have := List.all_eq_true.mp paths_ok s (List.mem_range.mpr h)
  simpa using this

theorem codeBits_length (s : Nat) (h : s < 257) :
    5 ≤ (codeBits s).length ∧ (codeBits s).length ≤ 30 := by
  have := List.all_eq_true.mp code_lengths s (List.mem_range.mpr h)
  simp only [Bool.and_eq_true, decide_eq_true_eq] at this
  simp only [codeBits, bitsOf_length]
  exact this

theorem codeBits_ne_nil (s : Nat) (h : s < 257) : codeBits s ≠ [] := by
  intro he
  have := (codeBits_length s h).1
  rw [he] at this
  simp at this

/-! ## The decoder's steps -/

/-- Reading a code from where the walk is takes the decoder to that symbol. -/
theorem decode_code (lim : Nat) (t : Tree) (p : List Bool) (x : Nat) (hp : p ≠ [])
    (hw : t.walk p = .leaf x) (rest : List Bool) (depth : Nat) (ones : Bool) (count : Nat)
    (out : List Nat) :
    decodeBits lim (p ++ rest) t depth ones count out =
      if x = eos then .error .invalid
      else if lim ≤ count then .error .tooLong
      else decodeBits lim rest tree 0 true (count + 1) (x :: out) := by
  induction p generalizing t depth ones with
  | nil => exact absurd rfl hp
  | cons b p ih =>
    rcases walk_to_leaf t b p x hw with ⟨rfl, hc⟩ | ⟨z, o, hc, hw'⟩
    · simp only [List.cons_append, List.nil_append, decodeBits, hc]
    · have hp' : p ≠ [] := by
        rintro rfl; simp [Tree.walk] at hw'
      simp only [List.cons_append, decodeBits, hc]
      exact ih (.node z o) hp' hw' _ _

/-- Bits that stay inside the tree end the string: it is accepted exactly when
fewer than eight bits are left since the last symbol, all ones. -/
theorem decode_inside (lim : Nat) (t : Tree) (q : List Bool) (hq : (t.walk q).isNode = true)
    (ht : t.isNode = true) (depth : Nat) (ones : Bool) (count : Nat) (out : List Nat) :
    decodeBits lim q t depth ones count out =
      if depth + q.length < 8 ∧ (ones && q.all id) = true then .ok out.reverse
      else .error .invalid := by
  induction q generalizing t depth ones with
  | nil => simp [decodeBits]
  | cons b q ih =>
    simp only [Tree.walk] at hq
    match hc : t.child b with
    | .leaf y =>
      rw [hc] at hq
      cases q <;> simp [Tree.walk, Tree.child, Tree.isNode, walk_empty] at hq
    | .empty => rw [hc] at hq; simp [walk_empty, Tree.isNode] at hq
    | .node z o =>
      rw [hc] at hq
      simp only [decodeBits, hc]
      rw [ih (.node z o) hq rfl]
      simp only [List.length_cons, List.all_cons, Bool.and_assoc, id,
        show depth + 1 + q.length = depth + (q.length + 1) by omega]
      by_cases hh : depth + (q.length + 1) < 8 ∧ (ones && (b && q.all id)) = true <;> simp only [hh, ite_true, ite_false]

theorem tree_isNode : tree.isNode = true := by
  have := List.all_eq_true.mp ones_ok.1 0 (by simp)
  simpa [Tree.walk] using this

theorem decode_ones (lim k : Nat) (hk : k < 8) (count : Nat) (out : List Nat) :
    decodeBits lim (List.replicate k true) tree 0 true count out = .ok out.reverse := by
  have hn := List.all_eq_true.mp ones_ok.1 k (List.mem_range.mpr (by omega))
  rw [decode_inside lim tree _ hn tree_isNode]
  simp [hk]

/-- The codes of octets within the limit are read as those octets, and the decoder
is back at the root for whatever follows. -/
theorem decode_after (lim : Nat) (s : List Nat) (hs : ∀ x ∈ s, x < 256) (rest : List Bool)
    (count : Nat) (out : List Nat) (hl : count + s.length ≤ lim) :
    decodeBits lim (encodeBits s ++ rest) tree 0 true count out
      = decodeBits lim rest tree 0 true (count + s.length) (out.reverse ++ s).reverse := by
  induction s generalizing count out with
  | nil => simp [encodeBits]
  | cons x s ih =>
    have hx : x < 256 := hs x (by simp)
    simp only [encodeBits, List.flatMap_cons, List.append_assoc]
    rw [decode_code lim tree (codeBits x) x (codeBits_ne_nil x (by omega)) (tree_code x (by omega))]
    have h1 : ¬ x = eos := by unfold eos; omega
    have h2 : ¬ lim ≤ count := by simp at hl; omega
    simp only [h1, h2, ite_false]
    rw [show s.flatMap codeBits = encodeBits s from rfl,
      ih (fun y hy => hs y (by simp [hy])) (count + 1) (x :: out) (by simp at hl; omega)]
    simp [Nat.add_assoc, Nat.add_comm 1]

/-! ## Headline theorems -/

/-- Decoding the codes of any octets, followed by fewer than eight one bits, gives
the octets back, if there are no more of them than the limit. -/
theorem decode_codes (lim : Nat) (s : List Nat) (hs : ∀ x ∈ s, x < 256) (k : Nat) (hk : k < 8)
    (count : Nat) (out : List Nat) (hl : count + s.length ≤ lim) :
    decodeBits lim (encodeBits s ++ List.replicate k true) tree 0 true count out
      = .ok (out.reverse ++ s) := by
  rw [decode_after lim s hs _ count out hl, decode_ones lim k hk]
  simp

/-- Section 5.2 round trip: a string encoded decodes to itself within any limit
at least its length. -/
theorem decode_encode_huffman (lim : Nat) (s : List Nat) (hs : ∀ x ∈ s, x < 256)
    (hl : s.length ≤ lim) : decode lim (encode s) = .ok s := by
  unfold decode encode
  rw [unpack_pack _ (by simp [padLen]; omega)]
  have := decode_codes lim s hs (padLen (encodeBits s).length) (by unfold padLen; omega) 0 []
    (by omega)
  simpa using this

/-- The decoder accepts exactly encodings: whatever it accepts is the codes of
octets, at most `limit` of them, followed by fewer than eight one bits. -/
theorem decode_sound (lim : Nat) (bits : List Bool) (t : Tree) (depth : Nat) (ones : Bool)
    (count : Nat) (out res : List Nat) (q : List Bool)
    (hq : tree.walk q = t) (hd : q.length = depth) (ho : ones = q.all id)
    (hc : count = out.length) (hcl : count ≤ lim)
    (h : decodeBits lim bits t depth ones count out = .ok res) :
    ∃ s k, res = out.reverse ++ s ∧ (∀ x ∈ s, x < 256) ∧ count + s.length ≤ lim ∧ k < 8 ∧
      q ++ bits = encodeBits s ++ List.replicate k true := by
  induction bits generalizing t depth ones count out q with
  | nil =>
    simp only [decodeBits] at h
    split at h
    · next hc8 =>
      simp only [Except.ok.injEq] at h
      refine ⟨[], depth, by simp [h], by simp, by simp; omega, hc8.1, ?_⟩
      simp only [List.append_nil, encodeBits, List.flatMap_nil, List.nil_append]
      have hall : q.all id = true := by rw [← ho]; exact hc8.2
      rw [← hd]
      exact List.eq_replicate_iff.mpr ⟨rfl, by simpa using hall⟩
    · cases h
  | cons b bs ih =>
    simp only [decodeBits] at h
    have hw : tree.walk (q ++ [b]) = t.child b := by rw [walk_append, hq]
    match hcb : t.child b, h with
    | .leaf y, h =>
      simp only at h
      split at h
      · cases h
      · next hy =>
        split at h
        · cases h
        · next hlim =>
          rw [hcb] at hw
          obtain ⟨hy257, hpath⟩ := tree_leaf_code _ _ hw
          obtain ⟨s, k, hres, hs, hsl, hk, hbits⟩ :=
            ih tree 0 true (count + 1) (y :: out) [] rfl rfl rfl (by simp [hc]) (by omega) h
          refine ⟨y :: s, k, by simp [hres], ?_, by simp; omega, hk, ?_⟩
          · intro x hx
            simp only [List.mem_cons] at hx
            rcases hx with rfl | hx
            · unfold eos at hy; omega
            · exact hs x hx
          · simp only [List.nil_append] at hbits
            rw [show q ++ b :: bs = (q ++ [b]) ++ bs by simp, hpath, hbits]
            simp [encodeBits]
    | .node z o, h =>
      simp only at h
      rw [hcb] at hw
      obtain ⟨s, k, hres, hs, hsl, hk, hbits⟩ :=
        ih (.node z o) (depth + 1) (ones && b) count out (q ++ [b]) hw (by simp [hd])
          (by simp [ho]) hc hcl h
      exact ⟨s, k, hres, hs, hsl, hk, by simpa using hbits⟩
    | .empty, h => simp only at h; cases h

/-- What `decode` accepts, as bytes: exactly the encodings of at most `limit` octets
padded with fewer than eight one bits. -/
theorem decode_exact (lim : Nat) (bytes : Bytes) (s : List Nat) (hb : ∀ b ∈ bytes, b < 256) :
    decode lim bytes = .ok s ↔
      (∀ x ∈ s, x < 256) ∧ s.length ≤ lim ∧
      ∃ k, k < 8 ∧ bytes = pack (encodeBits s ++ List.replicate k true) ∧
        (encodeBits s ++ List.replicate k true).length % 8 = 0 := by
  constructor
  · intro h
    obtain ⟨s', k, hres, hs, hsl, hk, hbits⟩ :=
      decode_sound lim (unpack bytes) tree 0 true 0 [] s [] rfl rfl rfl rfl (Nat.zero_le _) h
    simp only [List.reverse_nil, List.nil_append] at hres hbits
    subst hres
    refine ⟨hs, by omega, k, hk, ?_, ?_⟩
    · rw [← hbits, pack_unpack bytes hb]
    · rw [← hbits, unpack_length]; omega
  · rintro ⟨hs, hl, k, hk, rfl, hm⟩
    unfold decode
    rw [unpack_pack _ hm]
    simpa using decode_codes lim s hs k hk 0 [] (by omega)

/-- Padding of eight or more bits is an error (section 5.2: "strictly longer than
7 bits"). -/
theorem padding_too_long (lim : Nat) (s : List Nat) (hs : ∀ x ∈ s, x < 256) (hl : s.length ≤ lim)
    (k : Nat) (hk : 8 ≤ k) (hm : (encodeBits s ++ List.replicate k true).length % 8 = 0) :
    decode lim (pack (encodeBits s ++ List.replicate k true)) = .error .invalid := by
  unfold decode
  rw [unpack_pack _ hm, decode_after lim s hs _ 0 [] (by omega)]
  by_cases h30 : k < 30
  · have hn := List.all_eq_true.mp ones_ok.1 k (List.mem_range.mpr h30)
    rw [decode_inside lim tree _ hn tree_isNode]
    simp; omega
  · rw [show List.replicate k true = List.replicate 30 true ++ List.replicate (k - 30) true by
      rw [List.replicate_append_replicate]; congr 1; omega]
    rw [decode_code lim tree _ eos (by simp) ones_ok.2]
    simp

/-- Padding that is not the most significant bits of EOS, that is, bits left
inside a code that are not all ones, is an error. -/
theorem padding_not_ones (lim : Nat) (s : List Nat) (hs : ∀ x ∈ s, x < 256) (hl : s.length ≤ lim)
    (q : List Bool) (hq : (tree.walk q).isNode = true) (hz : false ∈ q)
    (hm : (encodeBits s ++ q).length % 8 = 0) :
    decode lim (pack (encodeBits s ++ q)) = .error .invalid := by
  unfold decode
  rw [unpack_pack _ hm, decode_after lim s hs _ 0 [] (by omega),
    decode_inside lim tree q hq tree_isNode]
  have : q.all id = false := by
    rw [Bool.eq_false_iff]
    intro h
    have := List.all_eq_true.mp h false hz
    simp at this
  simp [this]

/-- EOS inside a string is an error (section 5.2), wherever it is and whatever
follows it. -/
theorem eos_refused (lim : Nat) (s : List Nat) (hs : ∀ x ∈ s, x < 256) (hl : s.length ≤ lim)
    (rest : List Bool) (hm : (encodeBits s ++ codeBits eos ++ rest).length % 8 = 0) :
    decode lim (pack (encodeBits s ++ codeBits eos ++ rest)) = .error .invalid := by
  unfold decode
  rw [unpack_pack _ hm, List.append_assoc, decode_after lim s hs _ 0 [] (by omega),
    decode_code lim tree _ eos (codeBits_ne_nil eos (by decide)) (tree_code eos (by decide))]
  simp

/-- More octets than the limit are refused as too long. -/
theorem too_long (lim : Nat) (s : List Nat) (hs : ∀ x ∈ s, x < 256) (hl : lim < s.length) :
    decode lim (encode s) = .error .tooLong := by
  unfold decode encode
  rw [unpack_pack _ (by simp [padLen]; omega)]
  have run : ∀ (s : List Nat), (∀ x ∈ s, x < 256) → ∀ (count : Nat) (out : List Nat),
      count ≤ lim → lim < count + s.length → ∀ k,
      decodeBits lim (encodeBits s ++ List.replicate k true) tree 0 true count out = .error .tooLong := by
    intro s
    induction s with
    | nil => intro _ count out h1 h2; simp at h2; omega
    | cons x s ih =>
      intro hs count out h1 h2 k
      have hx : x < 256 := hs x (by simp)
      simp only [encodeBits, List.flatMap_cons, List.append_assoc]
      rw [decode_code lim tree (codeBits x) x (codeBits_ne_nil x (by omega)) (tree_code x (by omega))]
      have h1' : ¬ x = eos := by unfold eos; omega
      simp only [h1', ite_false]
      split
      · rfl
      · exact ih (fun y hy => hs y (by simp [hy])) (count + 1) (x :: out) (by omega)
          (by simp at h2; omega) k
  exact run s hs 0 [] (Nat.zero_le _) (by omega) _

end Hpack
