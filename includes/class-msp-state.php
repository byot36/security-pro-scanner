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

    public function update_open_issues(string $category, array $fresh_items): void {
        $state = get_option(self::OPEN_ISSUES_OPTION, array());
        $state[$category] = $fresh_items;
        update_option(self::OPEN_ISSUES_OPTION, $state, false);
    }

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

    public function get_fixed_log(): array {
        return get_option(self::FIXED_LOG_OPTION, array());
    }

    public function log_fix(string $label): void {
        $log = get_option(self::FIXED_LOG_OPTION, array());
        array_unshift($log, array('label' => $label, 'time' => current_time('mysql')));
        $log = array_slice($log, 0, 20);
        update_option(self::FIXED_LOG_OPTION, $log, false);
    }

    public static function uninstall(): void {
        delete_option(self::OPEN_ISSUES_OPTION);
        delete_option(self::FIXED_LOG_OPTION);
    }
}
