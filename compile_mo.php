<?php
/**
 * Simple PO to MO converter script
 * Based on basic Gettext MO format
 */
function compile_po_to_mo($po_file, $mo_file) {
    if (!file_exists($po_file)) return false;
    
    $contents = file_get_contents($po_file);
    $items = [];
    
    // Simple regex to extract msgid and msgstr pairs
    // Note: This doesn't handle plural forms or multi-line strings perfectly,
    // but works for standard single strings.
    preg_match_all('/msgid\s+"(.*)"\s+msgstr\s+"(.*)"/u', $contents, $matches, PREG_SET_ORDER);
    
    foreach ($matches as $match) {
        if ($match[1] === "" && $match[2] !== "") continue; // skip header
        $items[$match[1]] = $match[2];
    }
    
    ksort($items);
    $num_items = count($items);
    
    // MO file header
    $output = pack('I*', 0x950412de, 0, $num_items, 28, 28 + ($num_items * 8), 0, 0);
    
    $ids_table = '';
    $strs_table = '';
    $ids_offsets = [];
    $strs_offsets = [];
    
    $current_id_offset = 28 + ($num_items * 16);
    foreach ($items as $id => $str) {
        $ids_offsets[] = [strlen($id), $current_id_offset];
        $ids_table .= $id . "\0";
        $current_id_offset += strlen($id) + 1;
    }
    
    $current_str_offset = $current_id_offset;
    foreach ($items as $id => $str) {
        $strs_offsets[] = [strlen($str), $current_str_offset];
        $strs_table .= $str . "\0";
        $current_str_offset += strlen($str) + 1;
    }
    
    // Build tables
    $tables = '';
    foreach ($ids_offsets as $offset) $tables .= pack('II', $offset[0], $offset[1]);
    foreach ($strs_offsets as $offset) $tables .= pack('II', $offset[0], $offset[1]);
    
    return file_put_contents($mo_file, $output . $tables . $ids_table . $strs_table);
}

$po = __DIR__ . "/languages/ip-login-restrictor-ja.po";
$mo = __DIR__ . "/languages/ip-login-restrictor-ja.mo";

if (compile_po_to_mo($po, $mo)) {
    echo "Successfully generated $mo\n";
} else {
    echo "Failed to generate $mo\n";
    exit(1);
}
