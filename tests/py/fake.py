# Usage: python your_script_name.py function_definition_list_file > converted_text_file
import re
import sys

def extract_types_from_args(arguments_str):
    """
    引数の文字列から型名のみを抽出する関数。
    """
    if not arguments_str.strip() or arguments_str.lower() == 'void':
        return ""
    
    # 引数をカンマで分割
    args_list = arguments_str.split(',')
    
    types_list = []
    for arg in args_list:
        # 型名と変数名を分離するための正規表現パターン
        # 最後に空白と変数名、そして必要に応じて[]や*を削除
        # 例: 'const char *s' -> 'const char *'
        #     'int x' -> 'int'
        #     'char *argv[]' -> 'char *[]'
        
        # 配列の[]と変数名をマッチさせる
        arg = re.sub(r'\s*(\w+)\s*\[.*?\]\s*$', '[]', arg.strip())
        
        # ポインタの*と変数名をマッチさせる
        arg = re.sub(r'\s*(\w+)\s*$', '', arg.strip())
        
        # 関数ポインタの場合など、複雑な型はそのままにする
        
        # 残った文字列を型として追加
        types_list.append(arg.strip())

    # 抽出した型をカンマ区切りの文字列に戻す
    return ", ".join(types_list)


def convert_to_fff(prototype):
    """
    C言語のプロトタイプ宣言をfffの形式に変換する関数。
    """
    pattern = re.compile(r'^\s*(?P<return_type>.*?)\s*(?P<function_name>\w+)\s*\((?P<arguments>.*?)\)\s*;')
    match = pattern.match(prototype)

    if not match:
        return None

    return_type = match.group('return_type').strip()
    function_name = match.group('function_name').strip()
    arguments = match.group('arguments').strip()
    
    # 引数リストから型名のみを抽出
    extracted_types = extract_types_from_args(arguments)
    
    if return_type.lower() == 'void':
        if extracted_types:
            return f"""DEFINE_FAKE_VOID_FUNC({function_name}, {extracted_types});
DECLARE_FAKE_VOID_FUNC({function_name}, {extracted_types});
    RESET_FAKE({function_name})"""
        else:
            return f"""DEFINE_FAKE_VOID_FUNC({function_name});
DECLARE_FAKE_VOID_FUNC({function_name});
    RESET_FAKE({function_name})"""
    else:
        if extracted_types:
            return f"""DEFINE_FAKE_VALUE_FUNC({return_type}, {function_name}, {extracted_types});
DECLARE_FAKE_VALUE_FUNC({return_type}, {function_name}, {extracted_types});
    RESET_FAKE({function_name})"""
        else:
            return f"""DEFINE_FAKE_VALUE_FUNC({return_type}, {function_name});
DECLARE_FAKE_VALUE_FUNC({return_type}, {function_name});
    RESET_FAKE({function_name})"""

def process_file(file_path):
    """
    ファイルからプロトタイプ宣言を読み込み、変換して表示する関数。
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or line.startswith('//'):
                    continue
                
                fff_declaration = convert_to_fff(line)
                if fff_declaration:
                    print(fff_declaration)
    except FileNotFoundError:
        print(f"Error: The file '{file_path}' was not found.", file=sys.stderr)
    except Exception as e:
        print(f"An error occurred: {e}", file=sys.stderr)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python your_script_name.py <input_file.h>", file=sys.stderr)
        sys.exit(1)
    
    input_file = sys.argv[1]
    process_file(input_file)
