import Http.Body

/-!
# Controls: where RFC 9112 recipients disagree, the decoder refuses

`request_agrees` would be empty if every recipient in `Rfc.Choices` read
every input the same way. These are inputs on which two recipients the RFC
allows frame the message differently, so a server that accepted them would
let a front end and a back end see different requests. The decoder refuses
each of them, as `request_agrees` needs it to.
-/

namespace Http.Controls

open Wire

/-- Every tolerance taken. -/
def lenient : Rfc.Choices :=
  { lfAlone := true, bareCrAsSp := true, consumeWsLines := true, unfold := true, emptyLines := 8,
    wordsAnyWs := true, teOverridesCl := true, clList := true }

/-- No tolerance taken but the empty lines and the repeated length, as the
server does. -/
def strict : Rfc.Choices :=
  { lfAlone := false, bareCrAsSp := false, consumeWsLines := false, unfold := false, emptyLines := 8,
    wordsAnyWs := false, teOverridesCl := false, clList := true }

def lim : Limits := { startLine := 8192, headerLine := 8192, headers := 100, head := 65536, bodyChunk := 8192 }

/-- `Transfer-Encoding` with `Content-Length` (section 6.3 item 3): a
recipient that lets the coding override reads a chunked body, one that
refuses the request reads nothing. The decoder refuses it. -/
def teAndCl : Bytes :=
  str "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"

theorem te_and_cl_splits_the_family :
    (Rfc.request lenient teAndCl).map (·.head.framing) = some .chunked ∧
      Rfc.request strict teAndCl = none := by
  decide +kernel

theorem te_and_cl_refused : (request1 lim teAndCl true).2 = .stop (.failed .transferEncodingAndContentLength) := by
  decide +kernel

/-- A bare LF ends the head early for a recipient that takes it as a line
end (section 2.2), and is not a line end for one that does not. -/
def bareLf : Bytes := str "GET / HTTP/1.1\r\nHost: a\n\r\nGET /admin HTTP/1.1\r\nHost: a\r\n\r\n"

theorem bare_lf_splits_the_family :
    (Rfc.request lenient bareLf).map (·.head.headEnd) = some 26 ∧ Rfc.request strict bareLf = none := by
  decide +kernel

theorem bare_lf_refused : (request1 lim bareLf true).2 = .stop (.failed .lineEnding) := by
  decide +kernel

/-- An obs-fold (section 5.2): a recipient that unfolds it reads a
`Transfer-Encoding` of `chunked`, one that refuses it reads nothing. -/
def obsFold : Bytes :=
  str "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding:\r\n chunked\r\n\r\n0\r\n\r\n"

theorem obs_fold_splits_the_family :
    (Rfc.request lenient obsFold).map (·.head.framing) = some .chunked ∧
      Rfc.request strict obsFold = none := by
  decide +kernel

theorem obs_fold_refused : (request1 lim obsFold true).2 = .stop (.failed .header) := by
  decide +kernel

end Http.Controls
