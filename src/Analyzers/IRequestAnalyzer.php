<?php

namespace TheRealMkadmi\Citadel\Analyzers;

use Illuminate\Http\Request;

interface IRequestAnalyzer {
    public function analyze(Request $request): float;
}
