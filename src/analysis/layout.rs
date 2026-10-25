//! Layered (Sugiyama-style) layout with orthogonal edge routing, in character cells.
//!
//! 1. DFS finds back edges (loops); they're routed down the right margin.
//! 2. Longest-path layering over the remaining DAG.
//! 3. Long edges get one dummy node per skipped layer, so their vertical runs
//!    pass between blocks instead of through them.
//! 4. Barycenter ordering, then x placement by repeated centring on neighbours.
//! 5. Each channel between two layers gets one horizontal "lane" per
//!    overlapping edge segment.

use super::cfg::EdgeKind;
use std::collections::{HashMap, HashSet};

pub struct Placed {
    pub id: u64,
    pub x: usize,
    pub y: usize,
    pub w: usize,
    pub h: usize,
}

pub struct EdgeCell {
    pub x: usize,
    pub y: usize,
    pub ch: char,
    pub kind: EdgeKind,
}

pub struct Layout {
    pub blocks: Vec<Placed>,
    pub cells: Vec<EdgeCell>,
    pub width: usize,
    pub height: usize,
}

const GAP: usize = 3;

fn rank(k: EdgeKind) -> u8 {
    match k {
        EdgeKind::False => 0,
        EdgeKind::Jump => 1,
        EdgeKind::True => 2,
    }
}

struct Chain {
    path: Vec<usize>,
    kind: EdgeKind,
    port_idx: usize,
    port_cnt: usize,
}

struct Seg {
    chain: usize,
    si: usize,
    l: usize,
    xs: isize,
    xt: isize,
    lane: usize,
}

fn reorder(layer: &mut Vec<usize>, pos: &mut [usize], nb: &[Vec<usize>]) {
    let keys: Vec<f64> = layer
        .iter()
        .enumerate()
        .map(|(i, &v)| {
            if nb[v].is_empty() {
                i as f64
            } else {
                nb[v].iter().map(|&u| pos[u] as f64).sum::<f64>() / nb[v].len() as f64
            }
        })
        .collect();
    let mut idx: Vec<usize> = (0..layer.len()).collect();
    idx.sort_by(|&a, &b| keys[a].partial_cmp(&keys[b]).unwrap_or(std::cmp::Ordering::Equal));
    let new: Vec<usize> = idx.iter().map(|&i| layer[i]).collect();
    *layer = new;
    for (i, &v) in layer.iter().enumerate() {
        pos[v] = i;
    }
}

/// nodes: (id, width, height). edges: (from id, to id, kind).
pub fn layout(nodes: &[(u64, usize, usize)], edges: &[(u64, u64, EdgeKind)], entry: u64) -> Layout {
    let n = nodes.len();
    if n == 0 {
        return Layout { blocks: vec![], cells: vec![], width: 0, height: 0 };
    }
    let idx: HashMap<u64, usize> = nodes.iter().enumerate().map(|(i, nd)| (nd.0, i)).collect();
    let mut succ: Vec<Vec<(usize, EdgeKind)>> = vec![vec![]; n];
    for &(a, b, k) in edges {
        if let (Some(&i), Some(&j)) = (idx.get(&a), idx.get(&b)) {
            succ[i].push((j, k));
        }
    }
    for s in &mut succ {
        s.sort_by_key(|&(_, k)| rank(k)); // false (left) before true (right)
    }

    // ---- 1. DFS: preorder, postorder, back edges (iterative) ----
    let root = idx.get(&entry).copied().unwrap_or(0);
    let mut state = vec![0u8; n];
    let mut pre: Vec<usize> = Vec::new();
    let mut post: Vec<usize> = Vec::new();
    let mut back: HashSet<(usize, usize)> = HashSet::new();
    for r in std::iter::once(root).chain(0..n) {
        if state[r] != 0 {
            continue;
        }
        let mut stack: Vec<(usize, usize)> = vec![(r, 0)];
        state[r] = 1;
        pre.push(r);
        while !stack.is_empty() {
            let (v, ci) = *stack.last().unwrap();
            if ci < succ[v].len() {
                stack.last_mut().unwrap().1 += 1;
                let w = succ[v][ci].0;
                match state[w] {
                    0 => {
                        state[w] = 1;
                        pre.push(w);
                        stack.push((w, 0));
                    }
                    1 => {
                        back.insert((v, w));
                    }
                    _ => {}
                }
            } else {
                state[v] = 2;
                post.push(v);
                stack.pop();
            }
        }
    }

    // ---- 2. layering ----
    let mut depth = vec![0usize; n];
    for &v in post.iter().rev() {
        for &(w, _) in &succ[v] {
            if !back.contains(&(v, w)) {
                depth[w] = depth[w].max(depth[v] + 1);
            }
        }
    }
    let mut fwd: Vec<Vec<(usize, EdgeKind)>> = vec![vec![]; n];
    let mut back_edges: Vec<(usize, usize, EdgeKind)> = Vec::new();
    for v in 0..n {
        for &(t, k) in &succ[v] {
            if back.contains(&(v, t)) {
                back_edges.push((v, t, k));
            } else {
                fwd[v].push((t, k));
            }
        }
    }

    // ---- 3. dummy nodes for long edges ----
    let max_depth = *depth.iter().max().unwrap();
    let mut layers: Vec<Vec<usize>> = vec![vec![]; max_depth + 1];
    let mut w: Vec<usize> = nodes.iter().map(|nd| nd.1).collect();
    let mut h: Vec<usize> = nodes.iter().map(|nd| nd.2).collect();
    let mut lay: Vec<usize> = depth.clone();
    let mut up: Vec<Vec<usize>> = vec![vec![]; n];
    let mut down: Vec<Vec<usize>> = vec![vec![]; n];
    let mut chains: Vec<Chain> = Vec::new();
    for &v in &pre {
        layers[depth[v]].push(v);
        for (ei, &(t, k)) in fwd[v].iter().enumerate() {
            let mut path = vec![v];
            for l in depth[v] + 1..depth[t] {
                let d = w.len();
                w.push(1);
                h.push(0);
                lay.push(l);
                up.push(vec![]);
                down.push(vec![]);
                layers[l].push(d);
                path.push(d);
            }
            path.push(t);
            chains.push(Chain { path, kind: k, port_idx: ei, port_cnt: fwd[v].len() });
        }
    }
    for c in &chains {
        for p in c.path.windows(2) {
            down[p[0]].push(p[1]);
            up[p[1]].push(p[0]);
        }
    }
    let total = w.len();
    let nl = layers.len();

    // ---- 4a. ordering ----
    let mut pos = vec![0usize; total];
    for layer in &layers {
        for (i, &v) in layer.iter().enumerate() {
            pos[v] = i;
        }
    }
    for pass in 0..3 {
        if pass % 2 == 0 {
            for l in 1..nl {
                reorder(&mut layers[l], &mut pos, &up);
            }
        } else {
            for l in (0..nl.saturating_sub(1)).rev() {
                reorder(&mut layers[l], &mut pos, &down);
            }
        }
    }

    // ---- 4b. x placement ----
    let mut x = vec![0isize; total];
    for layer in &layers {
        let mut c = 0isize;
        for &v in layer {
            x[v] = c;
            c += (w[v] + GAP) as isize;
        }
    }
    for pass in 0..4 {
        let top_down = pass % 2 == 0;
        let order: Vec<usize> = if top_down { (0..nl).collect() } else { (0..nl).rev().collect() };
        for l in order {
            let mut cursor = 0isize;
            for &v in &layers[l] {
                let nb = if top_down { &up[v] } else { &down[v] };
                let want = if nb.is_empty() {
                    x[v]
                } else {
                    let s: isize = nb.iter().map(|&u| x[u] + (w[u] / 2) as isize).sum();
                    s / nb.len() as isize - (w[v] / 2) as isize
                };
                x[v] = want.max(cursor);
                cursor = x[v] + (w[v] + GAP) as isize;
            }
        }
    }
    let cen = |v: usize| x[v] + (w[v] / 2) as isize;

    // ---- 5. segments, lanes, channel heights ----
    let mut segs: Vec<Seg> = Vec::new();
    for (ci, c) in chains.iter().enumerate() {
        for si in 0..c.path.len() - 1 {
            let a = c.path[si];
            let b = c.path[si + 1];
            let xs = if si == 0 {
                cen(a) + (2 * c.port_idx as isize - (c.port_cnt as isize - 1))
            } else {
                cen(a)
            };
            segs.push(Seg { chain: ci, si, l: lay[a], xs, xt: cen(b), lane: 0 });
        }
    }
    let mut lanes: Vec<Vec<Vec<(isize, isize)>>> = vec![vec![]; nl];
    for s in segs.iter_mut() {
        if s.xs == s.xt {
            continue;
        }
        let (lo, hi) = (s.xs.min(s.xt), s.xs.max(s.xt));
        let ch = &mut lanes[s.l];
        let mut found = None;
        for (k, lane) in ch.iter().enumerate() {
            if lane.iter().all(|&(a, b)| hi + 1 < a || b + 1 < lo) {
                found = Some(k);
                break;
            }
        }
        let k = match found {
            Some(k) => k,
            None => {
                ch.push(vec![]);
                ch.len() - 1
            }
        };
        ch[k].push((lo, hi));
        s.lane = k;
    }
    let hl: Vec<usize> = layers
        .iter()
        .map(|l| l.iter().map(|&v| h[v]).max().unwrap_or(0).max(1))
        .collect();
    let chh: Vec<usize> = lanes.iter().map(|l| l.len() + 2).collect();
    let mut layer_y = vec![0usize; nl];
    for l in 1..nl {
        layer_y[l] = layer_y[l - 1] + hl[l - 1] + chh[l - 1];
    }
    let height = layer_y[nl - 1] + hl[nl - 1];

    // ---- 6. edge cells ----
    let mut cells: Vec<EdgeCell> = Vec::new();
    {
        let mut push = |xx: isize, yy: usize, ch: char, k: EdgeKind| {
            cells.push(EdgeCell { x: xx.max(0) as usize, y: yy, ch, kind: k });
        };
        for s in &segs {
            let c = &chains[s.chain];
            let a = c.path[s.si];
            let b = c.path[s.si + 1];
            let l = s.l;
            let y0 = layer_y[l] + hl[l];
            let nlanes = lanes[l].len();
            let start_y = if a < n { layer_y[l] + h[a] } else { layer_y[l] };
            for yy in start_y..y0 {
                push(s.xs, yy, '│', c.kind);
            }
            let label = if s.si == 0 && a < n {
                match c.kind {
                    EdgeKind::False => 'f',
                    EdgeKind::True => 't',
                    EdgeKind::Jump => '│',
                }
            } else {
                '│'
            };
            push(s.xs, y0, label, c.kind);
            if s.xs == s.xt {
                for r in 1..=nlanes {
                    push(s.xs, y0 + r, '│', c.kind);
                }
            } else {
                let ly = y0 + 1 + s.lane;
                for yy in y0 + 1..ly {
                    push(s.xs, yy, '│', c.kind);
                }
                let (cs, ct) = if s.xt > s.xs { ('└', '┐') } else { ('┘', '┌') };
                push(s.xs, ly, cs, c.kind);
                for xx in s.xs.min(s.xt) + 1..s.xs.max(s.xt) {
                    push(xx, ly, '─', c.kind);
                }
                push(s.xt, ly, ct, c.kind);
                for yy in ly + 1..=y0 + nlanes {
                    push(s.xt, yy, '│', c.kind);
                }
            }
            push(s.xt, y0 + nlanes + 1, if b < n { '▼' } else { '│' }, c.kind);
        }
    }

    // ---- 7. blocks and back edges ----
    let blocks: Vec<Placed> = (0..n)
        .map(|v| Placed { id: nodes[v].0, x: x[v] as usize, y: layer_y[lay[v]], w: w[v], h: h[v] })
        .collect();
    let nodes_w = (0..total).map(|v| x[v] as usize + w[v]).max().unwrap_or(0);
    for (k, &(s, t, kind)) in back_edges.iter().enumerate() {
        let xm = nodes_w + 2 + 2 * k;
        let (ps, pt) = (&blocks[s], &blocks[t]);
        let rs = ps.y + ps.h - 2;
        let rt = pt.y + 1;
        let mut push = |xx: usize, yy: usize, ch: char| cells.push(EdgeCell { x: xx, y: yy, ch, kind });
        for xx in ps.x + ps.w..xm {
            push(xx, rs, '─');
        }
        push(xm, rs, '┘');
        for yy in rt + 1..rs {
            push(xm, yy, '│');
        }
        push(xm, rt, '┐');
        for xx in pt.x + pt.w + 1..xm {
            push(xx, rt, '─');
        }
        push(pt.x + pt.w, rt, '◀');
    }
    let width = nodes_w + 3 + 2 * back_edges.len();

    Layout { blocks, cells, width, height }
}
