<?php
namespace TheRealMkadmi\Citadel\Components;
use Illuminate\View\Component;

class Fingerprint extends Component
{
    /**
     * Create a new component instance.
     *
     * @return void
     */
    public function __construct()
    {
        // Constructor can receive parameters if needed
    }

    /**
     * Get the view / contents that represent the component.
     *
     * @return \Illuminate\Contracts\View\View|\Closure|string
     */
    public function render()
    {
        return view('citadel::fingerprint');
    }
}
