/**
 * Schema Validator — Lightweight JSON Schema 2020-12 Subset
 *
 * Zero external dependencies. Supports only the features used by our schemas:
 * type, required, properties, const, enum, pattern, minimum, minLength,
 * additionalProperties, format, items, $ref, $defs.
 */

type Schema = Record<string, unknown>;

export interface ValidationResult {
  valid: boolean;
  errors: string[];
}

/**
 * Validate data against a JSON Schema (2020-12 subset).
 *
 * @param data - The value to validate
 * @param schema - A JSON Schema object
 * @returns Validation result with any errors
 */
export function validateAgainstSchema(
  data: unknown,
  schema: Schema,
): ValidationResult {
  const errors: string[] = [];
  validateNode(data, schema, '', errors, schema);
  return { valid: errors.length === 0, errors };
}

// ---------------------------------------------------------------------------
// Internal
// ---------------------------------------------------------------------------

function validateNode(
  data: unknown,
  schema: Schema,
  path: string,
  errors: string[],
  root: Schema,
): void {
  // Handle $ref — resolve from root $defs
  if (typeof schema['$ref'] === 'string') {
    const resolved = resolveRef(schema['$ref'] as string, root);
    if (!resolved) {
      errors.push(`${path}: unresolvable $ref "${schema['$ref']}"`);
      return;
    }
    validateNode(data, resolved, path, errors, root);
    return;
  }

  // const
  if ('const' in schema) {
    if (data !== schema['const']) {
      errors.push(`${path}: expected const ${JSON.stringify(schema['const'])}, got ${JSON.stringify(data)}`);
    }
    return;
  }

  // enum
  if (Array.isArray(schema['enum'])) {
    const allowed = schema['enum'] as unknown[];
    if (!allowed.includes(data)) {
      errors.push(`${path}: value ${JSON.stringify(data)} not in enum [${allowed.map(v => JSON.stringify(v)).join(', ')}]`);
    }
    return;
  }

  // type
  if (typeof schema['type'] === 'string') {
    if (!checkType(data, schema['type'] as string)) {
      errors.push(`${path}: expected type "${schema['type']}", got ${typeOf(data)}`);
      return; // Stop further checks — type mismatch
    }
  }

  // --- string checks ---
  if (typeof data === 'string') {
    if (typeof schema['minLength'] === 'number' && data.length < (schema['minLength'] as number)) {
      errors.push(`${path}: string length ${data.length} < minLength ${schema['minLength']}`);
    }
    if (typeof schema['pattern'] === 'string') {
      const re = new RegExp(schema['pattern'] as string);
      if (!re.test(data)) {
        errors.push(`${path}: string "${data}" does not match pattern "${schema['pattern']}"`);
      }
    }
    if (typeof schema['format'] === 'string') {
      validateFormat(data, schema['format'] as string, path, errors);
    }
  }

  // --- number / integer checks ---
  if (typeof data === 'number') {
    if (typeof schema['minimum'] === 'number' && data < (schema['minimum'] as number)) {
      errors.push(`${path}: value ${data} < minimum ${schema['minimum']}`);
    }
  }

  // --- array checks ---
  if (Array.isArray(data)) {
    if (schema['items'] && typeof schema['items'] === 'object') {
      for (let i = 0; i < data.length; i++) {
        validateNode(data[i], schema['items'] as Schema, `${path}[${i}]`, errors, root);
      }
    }
  }

  // --- object checks ---
  if (typeof data === 'object' && data !== null && !Array.isArray(data)) {
    const obj = data as Record<string, unknown>;

    // required
    if (Array.isArray(schema['required'])) {
      for (const key of schema['required'] as string[]) {
        if (!(key in obj)) {
          errors.push(`${path}: missing required property "${key}"`);
        }
      }
    }

    // properties
    if (typeof schema['properties'] === 'object' && schema['properties'] !== null) {
      const props = schema['properties'] as Record<string, Schema>;
      for (const [key, propSchema] of Object.entries(props)) {
        if (key in obj) {
          validateNode(obj[key], propSchema, path ? `${path}.${key}` : key, errors, root);
        }
      }
    }

    // additionalProperties
    if (schema['additionalProperties'] === false) {
      const allowed = schema['properties']
        ? new Set(Object.keys(schema['properties'] as object))
        : new Set<string>();
      for (const key of Object.keys(obj)) {
        if (!allowed.has(key)) {
          errors.push(`${path}: unexpected additional property "${key}"`);
        }
      }
    }

    // additionalProperties as schema (for Record-like types)
    if (
      typeof schema['additionalProperties'] === 'object' &&
      schema['additionalProperties'] !== null
    ) {
      const knownKeys = schema['properties']
        ? new Set(Object.keys(schema['properties'] as object))
        : new Set<string>();
      for (const [key, val] of Object.entries(obj)) {
        if (!knownKeys.has(key)) {
          validateNode(val, schema['additionalProperties'] as Schema, path ? `${path}.${key}` : key, errors, root);
        }
      }
    }
  }
}

/**
 * Resolve a JSON Pointer $ref (only supports `#/$defs/Name` style).
 */
function resolveRef(ref: string, root: Schema): Schema | null {
  if (!ref.startsWith('#/')) return null;
  const segments = ref.slice(2).split('/');
  let current: unknown = root;
  for (const seg of segments) {
    if (typeof current !== 'object' || current === null) return null;
    current = (current as Record<string, unknown>)[seg];
  }
  return typeof current === 'object' && current !== null ? current as Schema : null;
}

/**
 * Check whether data matches a JSON Schema type keyword.
 */
function checkType(data: unknown, type: string): boolean {
  switch (type) {
    case 'string':
      return typeof data === 'string';
    case 'number':
      return typeof data === 'number' && isFinite(data);
    case 'integer':
      return typeof data === 'number' && Number.isInteger(data);
    case 'boolean':
      return typeof data === 'boolean';
    case 'array':
      return Array.isArray(data);
    case 'object':
      return typeof data === 'object' && data !== null && !Array.isArray(data);
    case 'null':
      return data === null;
    default:
      return true;
  }
}

/**
 * Validate the `format` keyword (best-effort, not strict).
 */
function validateFormat(value: string, format: string, path: string, errors: string[]): void {
  switch (format) {
    case 'date-time': {
      // ISO 8601 date-time: must parse and not be NaN
      const d = Date.parse(value);
      if (isNaN(d)) {
        errors.push(`${path}: invalid date-time format "${value}"`);
      }
      // Also check basic ISO-8601 shape
      if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(value)) {
        errors.push(`${path}: date-time must be ISO 8601 format "${value}"`);
      }
      break;
    }
    case 'uri': {
      if (!/^https?:\/\/.+/.test(value)) {
        errors.push(`${path}: invalid URI format "${value}"`);
      }
      break;
    }
    // Unknown formats are silently accepted (per JSON Schema spec)
  }
}

/**
 * Return a human-readable type name for error messages.
 */
function typeOf(data: unknown): string {
  if (data === null) return 'null';
  if (Array.isArray(data)) return 'array';
  return typeof data;
}
