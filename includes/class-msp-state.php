<?php
if (!defined('ABSPATH')) {
    exit;
}

/**
 * Holds the real, current state of open issues and confirmed fixes.
 * Unlike the log table (raw history), here each category completely
 * overwrites its results on every scan — anything fixed in the meantime
 * disappears automatically instead of accumulating indefinitely.
 */
class MSP_State {

    const OPEN_ISSUES_OPTION = 'sp_open_issues';
    const FIXED_LOG_OPTION   = 'sp_fixed_log';

    /**
     * Overwrites one category's findings with the results of the latest scan.
     *
     * @param string $category    Scan module identifier (e.g. 'headers', 'sqli').
     * @param array  $fresh_items Findings from the most recent scan of this category.
     * @return void
     */
    public function update_open_issues(string $category, array $fresh_items): void {
        $state = get_option(self::OPEN_ISSUES_OPTION, array());
        $state[$category] = $fresh_items;
        update_option(self::OPEN_ISSUES_OPTION, $state, false);
    }

    /**
     * Flattens all categories into a single list, sorted by severity
     * (CRITICAL, then WARNING, then INFO).
     *
     * @return array
     */
    public function get_open_issues(): array {
        $state = get_option(self::OPEN_ISSUES_OPTION, array());
        $flat = array();
        foreach ($state as $category => $items) {
            foreach ($items as $item) {
                $item['category'] = $category;
                $flat[] = $item;
            }
        }

        $order = array('CRITICAL' => 0, 'WARNING' => 1, 'INFO' => 2);
        usort($flat, function ($a, $b) use ($order) {
            return ($order[$a['level']] ?? 3) <=> ($order[$b['level']] ?? 3);
        });

        return $flat;
    }

    /**
     * Returns the most recent confirmed fixes (newest first).
     *
     * @return array
     */
    public function get_fixed_log(): array {
        return get_option(self::FIXED_LOG_OPTION, array());
    }

    /**
     * Records a confirmed fix at the top of the log, keeping only the last 20 entries.
     *
     * @param string $label Human-readable description of what was fixed.
     * @return void
     */
    public function log_fix(string $label): void {
        $log = get_option(self::FIXED_LOG_OPTION, array());
        array_unshift($log, array('label' => $label, 'time' => current_time('mysql')));
        $log = array_slice($log, 0, 20);
        update_option(self::FIXED_LOG_OPTION, $log, false);
    }

    /**
     * Removes all options owned by this class.
     *
     * @return void
     */
    public static function uninstall(): void {
        delete_option(self::OPEN_ISSUES_OPTION);
        delete_option(self::FIXED_LOG_OPTION);
    }
}
